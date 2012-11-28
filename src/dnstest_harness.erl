-module(dnstest_harness).
-behavior(gen_server).

-include("dns.hrl").

% API
-export([start_link/0]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-record(state, {}).

-define(SERVER, ?MODULE).

% Public API

%% Start the gen server.
start_link() ->
  lager:info("Starting ~p process", [?MODULE]),
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
  {ok, #state{}}.

handle_call(_Message, _From, State) ->
  {reply, ok, State}.

handle_cast({run, Definition}, State) ->
  TestResults = run(Definition),
  dnstest_reporter:report(TestResults),
  {noreply, State};
handle_cast({run_target, Definition, Names}, State) ->
  TestResults = run(Definition, Names),
  dnstest_reporter:report(TestResults),
  {noreply, State}.

handle_info(Message, State) ->
  lager:info("handle_info(~p)", [Message]),
  {noreply, State}.

terminate(Reason, _State) ->
  lager:info("terminate(~p)", [Reason]),
  ok.

code_change(PreviousVersion, State, Extra) ->
  lager:info("code_change(~p, ~p)", [PreviousVersion, Extra]),
  {ok, State}.

%% Internal API

% Run the test with the given definition.
run(Definition) -> run(Definition, [], []).
run(Definition, Names) -> run(Definition, Names, []).

run([], _, TestResults) -> TestResults;
run([{Name, Conditions}|Rest], Names, TestResults) ->
  case length(Names) of
    0 -> run(Rest, Names, TestResults ++ run_test(Name, Conditions));
    _ ->
      case lists:member(atom_to_list(Name), Names) of
        true -> run(Rest, Names, TestResults ++ run_test(Name, Conditions));
        false -> run(Rest, Names, TestResults)
      end
  end.

run_test(Name, Conditions) ->
  lager:info("Running test ~p", [Name]),

  {{question, {Qname, Qtype}}, {header, ExpectedHeader}, {records, ExpectedRecords}} = Conditions,
  {{answers, ExpectedAnswers}, {authority, ExpectedAuthority}, {additional, ExpectedAdditional}} = ExpectedRecords,

  % Run the test
  Questions = [#dns_query{name=Qname, type=Qtype}],
  Message = #dns_message{rd = false, qc=1, questions=Questions},
  {ok, Response} = send_udp_query(Message, {127,0,0,1}, 8053),
  lager:debug("Response: ~p", [Response]),

  % Check the results
  Results = [
    test_header(ExpectedHeader, Response),
    test_records(ExpectedAnswers, Response#dns_message.answers, answers),
    test_records(ExpectedAuthority, Response#dns_message.authority, authority),
    test_records(ExpectedAdditional, Response#dns_message.additional, additional)
  ],

  [{Name, Results}].

% Test expected answers against actual answers.
test_records(ExpectedRecords, ActualRecords, SectionType) ->
  ActualRecordsSorted = lists:sort(lists:map(fun({dns_rr, Name, Class, Type, TTL, Data}) ->
        {Name, Class, Type, TTL, Data}
    end, ActualRecords)),
  ExpectedRecordsSorted = lists:sort(ExpectedRecords),
  case ExpectedRecordsSorted =:= ActualRecordsSorted of
    false ->
      lager:info("Expected ~p: ~p", [SectionType, ExpectedRecordsSorted]),
      lager:info("Actual ~p: ~p", [SectionType, ActualRecordsSorted]),
      false;
    true -> true
  end.

% Test expected header values against actual header values.
test_header(ExpectedHeader, Response) ->
  ActualHeader = #dns_message{
    id=ExpectedHeader#dns_message.id,
    rc=Response#dns_message.rc,
    rd=Response#dns_message.rd,
    qr=Response#dns_message.qr,
    tc=Response#dns_message.tc,
    aa=Response#dns_message.aa,
    oc=Response#dns_message.oc
  },
  case ExpectedHeader =:= ActualHeader of
    false ->
      lager:info("Expected header: ~p", [ExpectedHeader]),
      lager:info("Actual header: ~p", [ActualHeader]),
      false;
    true -> true
  end.

% Send the message to the given host:port via UDP.
send_udp_query(Message, Host, Port) ->
  Packet = dns:encode_message(Message),
  lager:debug("Sending UDP query to ~p", [Host]),
  {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
  gen_udp:send(Socket, Host, Port, Packet),
  QueryResponse = case gen_udp:recv(Socket, 65535, 3000) of
    {ok, {Host, _Port, Reply}} -> {ok, dns:decode_message(Reply)};
    {error, Error} -> {error, Error, {server, {Host, Port}}};
    Response -> Response
  end,
  gen_udp:close(Socket),
  QueryResponse.
