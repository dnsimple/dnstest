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

handle_call({run, Definition}, _From, State) ->
  TestResults = run(Definition),
  {reply, TestResults, State}.

handle_cast(Message, State) ->
  lager:info("handle_cast(~p)", [Message]),
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
run(Definition) -> run(Definition, []).

run([], TestResults) -> TestResults;
run([{Name, Conditions}|Rest], TestResults) ->
  lager:info("Running test ~p", [Name]),

  {{question, {Qname, Qtype}}, {header, ExpectedHeader}, {records, ExpectedAnswers}} = Conditions,

  % Run the test
  Questions = [#dns_query{name=Qname, type=Qtype}],
  Message = #dns_message{rd = false, qc=1, questions=Questions},
  {ok, Response} = send_udp_query(Message, {127,0,0,1}, 8053),
  lager:info("Response: ~p", [Response]),

  % Check the results
  test_header(ExpectedHeader, Response),
  test_answers(ExpectedAnswers, Response),

  run(Rest, TestResults).

% Test expected answers against actual answers.
test_answers(ExpectedAnswers, Response) ->
  ActualAnswers = lists:map(fun({dns_rr, Name, Class, Type, TTL, Data}) ->
        {Name, Class, Type, TTL, Data}
  end, Response#dns_message.answers),

  MatchResult = ExpectedAnswers =:= ActualAnswers,
  lager:info("Expected answers: ~p", [ExpectedAnswers]),
  lager:info("Actual answers: ~p", [ActualAnswers]),
  lager:info("Answer match? ~p", [MatchResult]),
  MatchResult.

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
  MatchResult = ExpectedHeader =:= ActualHeader,
  lager:info("Expected header: ~p", [ExpectedHeader]),
  lager:info("Actual header: ~p", [ActualHeader]),
  lager:info("Header match? ~p", [MatchResult]),
  MatchResult.

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
