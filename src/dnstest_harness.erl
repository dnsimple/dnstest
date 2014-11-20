-module(dnstest_harness).
-behavior(gen_server).

-include_lib("dns/include/dns.hrl").

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

% Internal API
-export([send_request/3]).

-record(state, {}).

-define(SERVER, ?MODULE).
-define(DEFAULT_IPV4_ADDRESS, {127,0,0,1}).
-define(DEFAULT_IPV6_ADDRESS, {0,0,0,0,0,0,0,1}).
-define(DEFAULT_PORT, 53).

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
  dnstest_metrics:slowest(),
  {noreply, State};
handle_cast({run_target, Definition, Names}, State) ->
  TestResults = run(Definition, Names),
  dnstest_reporter:report(TestResults),
  dnstest_metrics:display(Names),
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

measure(Name, FunctionName, Args) when is_list(Args) ->
  {T, R} = timer:tc(?MODULE, FunctionName, Args),
  dnstest_metrics:insert(Name, T),
  R;
measure(Name, FunctionName, Arg) -> measure(Name, FunctionName, [Arg]). 

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

run_test(Name, {{question, {Qname, Qtype}}, {header, ExpectedHeader}, {records, ExpectedRecords}}) ->
  run_test(Name, {{question, {Qname, Qtype}}, {header, ExpectedHeader}, {options, []}, {records, ExpectedRecords}});
run_test(Name, Conditions) ->
  lager:info("Running test ~p", [Name]),

  {{question, {Qname, Qtype}}, {header, ExpectedHeader}, {options, Options}, {records, ExpectedRecords}} = Conditions,
  {{answers, ExpectedAnswers}, {authority, ExpectedAuthority}, {additional, ExpectedAdditional}} = ExpectedRecords,

  lager:debug("Sending to host ~p and port ~p", [host(), port()]),

  % Run the test
  {ok, Response} = measure(Name, send_request, [Qname, Qtype, Options]),
  lager:debug("Response: ~p", [Response]),

  % Check the results
  Results = [
    test_header(ExpectedHeader, Response),
    test_records(ExpectedAnswers, Response#dns_message.answers, answers),
    test_records(ExpectedAuthority, Response#dns_message.authority, authority),
    test_records(ExpectedAdditional, Response#dns_message.additional, additional)
  ],

  [{Name, Results}].

send_request(Qname, Qtype, Options) ->
  Questions = [#dns_query{name=Qname, type=Qtype}],
  Additional = case proplists:get_bool(dnssec, Options) of
                 true -> [#dns_optrr{dnssec=true}];
                 false -> []
               end,
  Message = #dns_message{rd = false, qc=1, adc=1, questions=Questions, additional=Additional},
  send_udp_query(Message, host(), port()).

% Test expected answers against actual answers.
test_records(ExpectedRecords, ActualRecords, SectionType) ->
  ActualRecordsSorted = lists:sort(lists:map(record_to_tuple_function(), lists:filter(dns_rr_filter(), ActualRecords))),
  ExpectedRecordsSorted = lists:sort(lists:map(fill_data_function(ActualRecordsSorted), ExpectedRecords)),

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
  QueryResponse = case gen_udp:recv(Socket, 65535, 6000) of
    {ok, {Host, _Port, Reply}} -> {ok, dns:decode_message(Reply)};
    {error, Error} -> {error, Error, {server, {Host, Port}}};
    Response -> Response
  end,
  gen_udp:close(Socket),
  QueryResponse.

host() ->
  host(inet4).

host(Key) when (Key =:= inet4) or (Key =:= inet6) ->
  case application:get_env(dnstest, Key) of
    {ok, Host} -> parse_address(Host);
    _ -> default_address(Key)
  end.

default_address(inet4) ->
  ?DEFAULT_IPV4_ADDRESS;
default_address(inet6) ->
  ?DEFAULT_IPV6_ADDRESS.

port() ->
  case application:get_env(dnstest, port) of
    {ok, Port} -> Port;
    _ -> ?DEFAULT_PORT
  end.

parse_address(Address) when is_list(Address) ->
  {ok, Tuple} = inet_parse:address(Address),
  Tuple;
parse_address(Address) -> Address.


fill_data(ExpectedName, ExpectedRRData, ActualRecords) when is_record(ExpectedRRData, dns_rrdata_rrsig) ->
  %lager:info("Expected RRData: ~p", [ExpectedRRData]),
  TypeCovered = ExpectedRRData#dns_rrdata_rrsig.type_covered,
  RRSigSet = lists:filter(rrsig_filter(ExpectedName, TypeCovered), ActualRecords),
  update_rrsig(ExpectedRRData, RRSigSet);

fill_data(ExpectedName, ExpectedRRData, ActualRecords) when is_record(ExpectedRRData, dns_rrdata_dnskey) ->
  Flags = ExpectedRRData#dns_rrdata_dnskey.flags,
  DNSKeySet = lists:filter(dnskey_filter(ExpectedName, Flags), ActualRecords),
  update_dnskey(ExpectedRRData, DNSKeySet);

fill_data(_, Data, _) -> Data.



update_rrsig(ExpectedRRData, []) -> ExpectedRRData;
update_rrsig(ExpectedRRData, [{_, _, _, _, Data}|_]) ->
  ExpectedRRData#dns_rrdata_rrsig{expiration = Data#dns_rrdata_rrsig.expiration,
                                  inception = Data#dns_rrdata_rrsig.inception,
                                  key_tag = Data#dns_rrdata_rrsig.key_tag,
                                  signature = Data#dns_rrdata_rrsig.signature
                                 }.

update_dnskey(ExpectedRRData, []) -> ExpectedRRData;
update_dnskey(ExpectedRRData, [{_, _, _, _, Data}|_]) ->
  ExpectedRRData#dns_rrdata_dnskey{
                                  key_tag = Data#dns_rrdata_dnskey.key_tag,
                                  public_key = Data#dns_rrdata_dnskey.public_key
                                 }.


record_to_tuple_function() ->
  fun({dns_rr, Name, Class, Type, TTL, Data}) ->
      {Name, Class, Type, TTL, Data}
  end.

fill_data_function(ActualRecordsSorted) ->
  fun({Name, Class, Type, TTL, Data}) ->
      {Name, Class, Type, TTL, fill_data(Name, Data, ActualRecordsSorted)}
  end.

dns_rr_filter() ->
  fun(R) ->
      case R of
        #dns_rr{} -> true;
        _ -> false
      end
  end.

rrsig_filter(ExpectedName, TypeCovered) ->
  fun({Name, _, _, _, RRData}) ->
      case {Name, RRData} of
        {ExpectedName, #dns_rrdata_rrsig{type_covered = TypeCovered}} ->
          %lager:info("RRData: ~p", [RRData]),
          true;
        _ -> false
      end
  end.

dnskey_filter(ExpectedName, Flags) ->
  fun({Name, _, _, _, RRData}) ->
      case {Name, RRData} of
        {ExpectedName, #dns_rrdata_dnskey{flags = Flags}} ->
          %lager:info("RRData: ~p", [RRData]),
          true;
        _ -> false
      end
  end.
