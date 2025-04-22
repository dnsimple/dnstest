-module(dnstest_harness).
-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

% API
-export([start_link/0, run/1, run/2, run_async/1, run_async/2]).

% Gen server hooks
-export([init/1, handle_call/3, handle_cast/2]).

% Internal API
-export([send_request/3]).

-opaque request() ::
    {run, [dnstest:definition()]}
    | {run_target, [dnstest:definition()], [dnstest:name()]}.

-type section() :: header | answers | authority | additional.

-type result() ::
    true
    | #{passing => [section()], failing => [section()]}
    | {error, term()}.

-type return() ::
    #{name := dnstest:name(), result := result(), time => undefined | non_neg_integer()}.

-export_type([request/0, result/0, return/0]).

-define(SERVER, ?MODULE).
-define(DEFAULT_IPV4_ADDRESS, {127, 0, 0, 1}).
-define(DEFAULT_PORT, 53).

% Public API

%% Start the gen server.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    ?LOG_INFO("Starting ~p process", [?MODULE]),
    gen_server:start_link({local, ?SERVER}, ?MODULE, noargs, []).

-spec run([dnstest:definition()]) -> [dnstest_harness:return()].
run(Definitions) ->
    gen_server:call(?SERVER, {run, Definitions}, infinity).

-spec run([dnstest:definition()], [dnstest:name()]) ->
    [dnstest_harness:return()].
run(Definitions, Names) ->
    gen_server:call(?SERVER, {run, Definitions, Names}, infinity).

-spec run_async([dnstest:definition()]) -> ok.
run_async(Definitions) ->
    gen_server:cast(?SERVER, {run, Definitions}).

-spec run_async([dnstest:definition()], [dnstest:name()]) -> ok.
run_async(Definitions, Names) ->
    gen_server:cast(?SERVER, {run, Definitions, Names}).

-spec init(noargs) -> {ok, no_state}.
init(noargs) ->
    {ok, no_state}.

-spec handle_call(request(), gen_server:from(), no_state) -> {reply, term(), no_state}.
handle_call({run, Definitions}, _From, State) ->
    TestResults = run_definitions(Definitions),
    dnstest_reporter:report(TestResults),
    dnstest_metrics:slowest(),
    {reply, TestResults, State};
handle_call({run, Definitions, Names}, _From, State) ->
    TestResults = run_definitions(Definitions, Names),
    dnstest_reporter:report(TestResults),
    dnstest_metrics:display(Names),
    {reply, TestResults, State}.

-spec handle_cast(request(), no_state) -> {noreply, no_state}.
handle_cast({run, Definitions}, State) ->
    TestResults = run_definitions(Definitions),
    dnstest_reporter:report(TestResults),
    dnstest_metrics:slowest(),
    {noreply, State};
handle_cast({run, Definitions, Names}, State) ->
    TestResults = run_definitions(Definitions, Names),
    dnstest_reporter:report(TestResults),
    dnstest_metrics:display(Names),
    {noreply, State}.

%% Internal API

-spec run_definitions([dnstest:definition()]) -> [return()].
run_definitions(Definitions) ->
    lists:map(fun run_test/1, Definitions).

-spec run_definitions([dnstest:definition()], [dnstest:name()]) -> [return()].
run_definitions(Definitions, Names) ->
    Targets = select_targets(Definitions, Names, []),
    lists:map(fun run_test/1, Targets).

select_targets([], _, Targets) ->
    lists:reverse(Targets);
select_targets([{Name, _Conditions} = Target | Rest], Names, Targets) ->
    case lists:member(atom_to_list(Name), Names) of
        true -> select_targets(Rest, Names, [Target | Targets]);
        false -> select_targets(Rest, Names, Targets)
    end.

-spec run_test(dnstest:definition()) -> return().
run_test({Name, Cond}) when is_map(Cond) ->
    try do_run_test(Name, Cond) of
        Result -> Result
    catch
        C:E:S ->
            #{name => Name, result => {error, {C, E, S}}}
    end.

do_run_test(Name, #{
    question := {Qname, Qtype},
    response := #{
        header := ExpectedHeader,
        answers := ExpectedAnswers,
        authority := ExpectedAuthority,
        additional := ExpectedAdditional
    } = Condition
}) ->
    Additional = maps:get(additional, Condition, []),
    ?LOG_INFO("Running test ~p", [Name]),
    % Run the test
    {Time, Result} = measure(Name, send_request, [Qname, Qtype, Additional]),
    case Result of
        {ok, Response} ->
            ?LOG_DEBUG("Response: ~p", [Response]),
            % Check the results
            QHeader = test_header(ExpectedHeader, Response),
            QAnswers = test_records(ExpectedAnswers, Response#dns_message.answers, answers),
            QAuthority = test_records(ExpectedAuthority, Response#dns_message.authority, authority),
            QAdditional = test_records(
                ExpectedAdditional, Response#dns_message.additional, additional
            ),
            Pass = QHeader andalso QAnswers andalso QAuthority andalso QAdditional,
            case Pass of
                true ->
                    #{name => Name, time => Time, result => true};
                false ->
                    Results = [
                        {header, QHeader},
                        {answers, QAnswers},
                        {authority, QAuthority},
                        {additional, QAdditional}
                    ],
                    Passing = lists:filtermap(
                        fun({Key, Value}) -> Value andalso {true, Key} end, Results
                    ),
                    Failing = lists:filtermap(
                        fun({Key, Value}) -> not Value andalso {true, Key} end, Results
                    ),
                    #{
                        name => Name,
                        time => Time,
                        result => #{passing => Passing, failing => Failing}
                    }
            end;
        {error, Error} ->
            {Name, Time, {error, Error}}
    end.

measure(Name, FunctionName, Args) when is_list(Args) ->
    {T, R} = timer:tc(?MODULE, FunctionName, Args, microsecond),
    dnstest_metrics:insert(Name, T),
    {T, R}.

-spec send_request(binary(), char(), dns:additional()) ->
    {ok, {dns:decode_error(), dns:message() | undefined, binary()} | dns:message()}
    | {error, {atom(), {server, {_, _}}}}.
send_request(Qname, Qtype, Additional) ->
    Questions = [#dns_query{name = Qname, type = Qtype}],
    Message = #dns_message{
        rd = false, qc = 1, adc = length(Additional), questions = Questions, additional = Additional
    },
    send_udp_query(Message, host(), port()).

% Test expected answers against actual answers.
test_records(ExpectedRecords, ActualRecords, SectionType) ->
    ActualRecordsSorted = lists:sort(
        lists:map(record_to_tuple_function(), lists:filter(dns_rr_filter(), ActualRecords))
    ),
    ExpectedRecordsSorted = lists:sort(
        lists:map(fill_data_function(ActualRecordsSorted), ExpectedRecords)
    ),

    case ExpectedRecordsSorted =:= ActualRecordsSorted of
        false ->
            ?LOG_INFO("Expected ~p: ~w", [SectionType, ExpectedRecordsSorted]),
            ?LOG_INFO("Actual ~p: ~w", [SectionType, ActualRecordsSorted]),
            false;
        true ->
            true
    end.

% Test expected header values against actual header values.
test_header(ExpectedHeader, Response) ->
    ActualHeader = #dns_message{
        id = ExpectedHeader#dns_message.id,
        rc = Response#dns_message.rc,
        rd = Response#dns_message.rd,
        qr = Response#dns_message.qr,
        tc = Response#dns_message.tc,
        aa = Response#dns_message.aa,
        oc = Response#dns_message.oc
    },
    case ExpectedHeader =:= ActualHeader of
        false ->
            ?LOG_INFO("Expected header: ~p", [ExpectedHeader]),
            ?LOG_INFO("Actual header: ~p", [ActualHeader]),
            false;
        true ->
            true
    end.

% Send the message to the given host:port via UDP.
send_udp_query(Message, Host, Port) ->
    Packet = dns:encode_message(Message),
    ?LOG_DEBUG("Sending UDP query to host ~p and port ~p", [host(), port()]),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, Host, Port, Packet),
    QueryResponse =
        case gen_udp:recv(Socket, 65535, 6000) of
            {ok, {Host, _Port, Reply}} when is_binary(Reply) -> {ok, dns:decode_message(Reply)};
            {error, Error} -> {error, {Error, {server, {Host, Port}}}}
        end,
    gen_udp:close(Socket),
    QueryResponse.

host() ->
    case application:get_env(dnstest, inet4) of
        {ok, Host} -> parse_address(Host);
        _ -> ?DEFAULT_IPV4_ADDRESS
    end.

port() ->
    case application:get_env(dnstest, port) of
        {ok, Port} -> Port;
        _ -> ?DEFAULT_PORT
    end.

parse_address(Address) when is_list(Address) ->
    {ok, Tuple} = inet_parse:address(Address),
    Tuple;
parse_address(Address) ->
    Address.

fill_data(ExpectedName, ExpectedRRData, ActualRecords) when
    is_record(ExpectedRRData, dns_rrdata_rrsig)
->
    %?LOG_INFO("Expected RRData: ~p", [ExpectedRRData]),
    TypeCovered = ExpectedRRData#dns_rrdata_rrsig.type_covered,
    RRSigSet = lists:filter(rrsig_filter(ExpectedName, TypeCovered), ActualRecords),
    update_rrsig(ExpectedRRData, RRSigSet);
fill_data(ExpectedName, ExpectedRRData, ActualRecords) when
    is_record(ExpectedRRData, dns_rrdata_dnskey)
->
    Flags = ExpectedRRData#dns_rrdata_dnskey.flags,
    DNSKeySet = lists:filter(dnskey_filter(ExpectedName, Flags), ActualRecords),
    update_dnskey(ExpectedRRData, DNSKeySet);
fill_data(_, Data, _) ->
    Data.

update_rrsig(ExpectedRRData, []) ->
    ExpectedRRData;
update_rrsig(ExpectedRRData, [{_, _, _, _, Data} | _]) ->
    ExpectedRRData#dns_rrdata_rrsig{
        expiration = Data#dns_rrdata_rrsig.expiration,
        inception = Data#dns_rrdata_rrsig.inception,
        key_tag = Data#dns_rrdata_rrsig.key_tag,
        signature = Data#dns_rrdata_rrsig.signature
    }.

update_dnskey(ExpectedRRData, []) ->
    ExpectedRRData;
update_dnskey(ExpectedRRData, [{_, _, _, _, Data} | _]) ->
    ExpectedRRData#dns_rrdata_dnskey{
        key_tag = Data#dns_rrdata_dnskey.key_tag,
        public_key = Data#dns_rrdata_dnskey.public_key
    }.

record_to_tuple_function() ->
    fun(#dns_rr{name = Name, type = Type, class = Class, ttl = TTL, data = Data}) ->
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
                %?LOG_INFO("RRData: ~p", [RRData]),
                true;
            _ ->
                false
        end
    end.

dnskey_filter(ExpectedName, Flags) ->
    fun({Name, _, _, _, RRData}) ->
        case {Name, RRData} of
            {ExpectedName, #dns_rrdata_dnskey{flags = Flags}} ->
                %?LOG_INFO("RRData: ~p", [RRData]),
                true;
            _ ->
                false
        end
    end.
