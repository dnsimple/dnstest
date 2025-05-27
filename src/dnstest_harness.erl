-module(dnstest_harness).
-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

% API
-export([start_link/0, run/1, run/2, run_async/1, run_async/2]).

% Gen server hooks
-export([init/1, handle_call/3, handle_cast/2]).

% Internal API
-export([send_request/4]).

% Helper functions for dnskey process (RSA)
-export([decode_dnskey_public_key/1, compute_base64_key/1]).

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
-define(LOG_INFO_PAD(Pad, Fmt, Args), ?LOG_INFO("|~s" ++ Fmt, [lists:duplicate(Pad, $\s) | Args])).

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
    ?LOG_INFO("--------------------------------------------------------"),
    try do_run_test(Name, Cond) of
        Result -> Result
    catch
        C:E:S ->
            #{name => Name, result => {error, {C, E, S}}}
    end.

do_run_test(
    Name,
    #{
        question := {Qname, Qtype},
        response := #{
            header := ExpectedHeader,
            answers := ExpectedAnswers,
            authority := ExpectedAuthority,
            additional := ExpectedAdditional
        }
    } = TestDefinitionMap
) ->
    Additional = maps:get(additional, TestDefinitionMap, []),
    % Default to UDP
    Transport = maps:get(transport, TestDefinitionMap, udp),
    % Log the additional section directory to STDOUT not using the logger
    ?LOG_INFO("Running test ~p via ~p", [Name, Transport]),
    % Run the test

    % Pass Transport
    {Time, Result} = measure(Name, send_request, [Qname, Qtype, Additional, Transport]),
    case Result of
        {ok, Response} ->
            ?LOG_DEBUG("Response: ~p", [Response]),
            IgnoreSections = maps:get(ignore, TestDefinitionMap, []),

            % Check the results
            QHeader = test_header(ExpectedHeader, Response),

            QAnswers =
                case lists:member(answers, IgnoreSections) of
                    true -> true;
                    false -> test_records(ExpectedAnswers, Response#dns_message.answers, answers)
                end,

            QAuthority =
                case lists:member(authority, IgnoreSections) of
                    true ->
                        true;
                    false ->
                        test_records(ExpectedAuthority, Response#dns_message.authority, authority)
                end,

            QAdditional =
                case lists:member(additional, IgnoreSections) of
                    true ->
                        true;
                    false ->
                        test_records(
                            ExpectedAdditional, Response#dns_message.additional, additional
                        )
                end,

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

-spec send_request(binary(), char(), dns:additional(), udp | tcp) ->
    {ok, {dns:decode_error(), dns:message() | undefined, binary()} | dns:message()}
    | {error, {atom(), {server, {_, _}}}}.
send_request(Qname, Qtype, Additional, Transport) ->
    Questions = [#dns_query{name = Qname, type = Qtype}],
    Message = #dns_message{
        rd = false, qc = 1, adc = length(Additional), questions = Questions, additional = Additional
    },
    case Transport of
        udp -> send_udp_query(Message, host(), port());
        tcp -> send_tcp_query(Message, host(), port())
    end.

% Test expected answers against actual answers.
test_records(ExpectedRecords, ActualRecords, SectionType) ->
    ActualRecordsSorted = lists:sort(
        lists:map(record_to_tuple_function(), lists:filter(dns_rr_filter(), ActualRecords))
    ),
    ExpectedRecordsSorted = lists:sort(
        lists:map(fill_data_function(ActualRecordsSorted), ExpectedRecords)
    ),

    case length(ExpectedRecordsSorted) =/= length(ActualRecordsSorted) of
        true ->
            ?LOG_INFO("Record count mismatch in ~p section.", [SectionType]),
            ?LOG_INFO("Expected (~p): ~p", [length(ExpectedRecordsSorted), ExpectedRecordsSorted]),
            ?LOG_INFO("Actual\s\s\s(~p): ~p", [length(ActualRecordsSorted), ActualRecordsSorted]),
            false;
        false ->
            ZippedRecords = lists:zip(ExpectedRecordsSorted, ActualRecordsSorted),
            lists:foldl(
                fun({Expected, Actual}, Acc) ->
                    case Expected =:= Actual of
                        true ->
                            % Continue if they match
                            Acc;
                        false ->
                            % Log detailed differences
                            compare_record_fields(Expected, Actual, SectionType),
                            % Mismatch found, overall result is false
                            false
                    end
                end,
                % Initial accumulator value (true means no mismatch found yet)
                true,
                ZippedRecords
            )
    end.

% Helper to compare fields of mismatched record tuples
-spec compare_record_fields(
    {dns:dname(), dns:class(), dns:type(), dns:ttl(), dns:rrdata()},
    {dns:dname(), dns:class(), dns:type(), dns:ttl(), dns:rrdata()},
    section()
) -> ok.
compare_record_fields(
    {NameE, ClassE, TypeE, TTLE, DataE}, {NameA, ClassA, TypeA, TTLA, DataA}, SectionType
) ->
    ?LOG_INFO("Record mismatch in ~p section:", [SectionType]),
    ?LOG_INFO_PAD(2, "Full Expected: ~p", [{NameE, ClassE, TypeE, TTLE, DataE}]),
    ?LOG_INFO_PAD(2, "Full Actual:\s\s\s~p", [{NameA, ClassA, TypeA, TTLA, DataA}]),
    case NameE =:= NameA of
        false ->
            ?LOG_INFO_PAD(4, "Field 'Name' mismatch: Expected ~p, Actual ~p", [NameE, NameA]);
        true ->
            ok
    end,
    case ClassE =:= ClassA of
        false ->
            ?LOG_INFO_PAD(4, "Field 'Class' mismatch: Expected ~p, Actual ~p", [ClassE, ClassA]);
        true ->
            ok
    end,
    case TypeE =:= TypeA of
        false ->
            ?LOG_INFO_PAD(
                4,
                "Field 'Type' mismatch: Expected ~p (~s), Actual ~p (~s)",
                [TypeE, dns_names:type_name(TypeE), TypeA, dns_names:type_name(TypeA)]
            );
        true ->
            ok
    end,
    case TTLE =:= TTLA of
        false ->
            ?LOG_INFO_PAD(4, "Field 'TTL' mismatch: Expected ~p, Actual ~p", [TTLE, TTLA]);
        true ->
            ok
    end,
    case DataE =:= DataA of
        false ->
            ?LOG_INFO_PAD(4, "Field 'Data' mismatch: Expected ~p, Actual ~p", [
                % record_to_string(DataE), record_to_string(DataA)
                DataE,
                DataA
            ]),
            % Add specific formatting for known binary-containing types
            % Check TypeE first, assuming Type mismatch was already caught if they differ.
            case TypeE of
                ?DNS_TYPE_RRSIG when
                    is_record(DataE, dns_rrdata_rrsig), is_record(DataA, dns_rrdata_rrsig)
                ->
                    SigE = binary_to_list(DataE#dns_rrdata_rrsig.signature),
                    SigA = binary_to_list(DataA#dns_rrdata_rrsig.signature),
                    case SigE =:= SigA of
                        false ->
                            ?LOG_INFO_PAD(6, "RRSIG Signature Hex: Expected ~s, Actual ~s", [
                                SigE, SigA
                            ]);
                        true ->
                            ok
                    end;
                ?DNS_TYPE_NSEC when
                    is_record(DataE, dns_rrdata_nsec), is_record(DataA, dns_rrdata_nsec)
                ->
                    MapE = DataE#dns_rrdata_nsec.types,
                    MapA = DataA#dns_rrdata_nsec.types,
                    case MapE =:= MapA of
                        false ->
                            ?LOG_INFO_PAD(6, "NSEC Type Bit Maps: Expected ~p, Actual ~p", [
                                MapE, MapA
                            ]);
                        true ->
                            ok
                    end;
                ?DNS_TYPE_TXT when
                    is_record(DataE, dns_rrdata_txt), is_record(DataA, dns_rrdata_txt)
                ->
                    TxtE = lists:map(
                        fun(Bin) -> binary_to_list(Bin) end, DataE#dns_rrdata_txt.txt
                    ),
                    TxtA = lists:map(
                        fun(Bin) -> binary_to_list(Bin) end, DataA#dns_rrdata_txt.txt
                    ),
                    case TxtE =:= TxtA of
                        false ->
                            ?LOG_INFO_PAD(6, "TXT Text Hex List: Expected ~p, Actual ~p", [
                                TxtE, TxtA
                            ]);
                        true ->
                            ok
                    end;
                _ ->
                    % No special hex formatting needed for other types' data fields
                    ok
            end;
        true ->
            ok
    end,
    ok.

-spec decode_dnskey_public_key(binary()) -> [integer(), ...].
decode_dnskey_public_key(Base64Key) ->
    % Remove any whitespace
    CleanKey = binary:replace(Base64Key, <<" ">>, <<"">>, [global]),

    % Decode from base64
    KeyBin = base64:decode(CleanKey),

    % Extract the format, exponent length, exponent, and modulus
    <<ExpLenByte:8, Rest/binary>> = KeyBin,

    % Handle exponent length
    {Exponent, ModulusBin} =
        case ExpLenByte of
            0 ->
                <<ExpLen:16, ExpRest/binary>> = Rest,
                <<Exp:ExpLen/unit:8, Mod/binary>> = ExpRest,
                {Exp, Mod};
            _ ->
                <<Exp:ExpLenByte/unit:8, Mod/binary>> = Rest,
                {Exp, Mod}
        end,

    % Convert modulus to integer
    Modulus = binary:decode_unsigned(ModulusBin),

    % Return as list [Exponent, Modulus] to match your original format
    [Exponent, Modulus].

-spec compute_base64_key(iodata()) -> binary().
compute_base64_key(PublicKey) ->
    % Extract exponent and modulus from the key
    [Exponent, Modulus] = PublicKey,

    % Encode exponent length (1 byte if exp <= 255, 3 bytes otherwise)
    ExpBytes =
        case Exponent of
            _ when Exponent =< 255 ->
                <<1:8, Exponent:8>>;
            _ when Exponent =< 16#FFFF ->
                <<2:8, Exponent:16>>;
            _ ->
                ExpSize = byte_size(binary:encode_unsigned(Exponent)),
                <<ExpSize:8, Exponent:(ExpSize * 8)>>
        end,

    % Encode modulus as binary
    ModulusBin = binary:encode_unsigned(Modulus),

    % Concatenate exponent and modulus
    KeyBin = <<ExpBytes/binary, ModulusBin/binary>>,

    % Convert to base32
    base64:encode(KeyBin).

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
            ?LOG_INFO("Actual header:\s\s\s~p", [ActualHeader]),
            false;
        true ->
            true
    end.

% Send the message to the given host:port via UDP.
send_udp_query(Message, Host, Port) ->
    Packet = dns:encode_message(Message),
    ?LOG_DEBUG("Sending UDP query to host ~p and port ~p", [Host, Port]),
    case gen_udp:open(0, [binary, {active, false}]) of
        {ok, Socket} ->
            try
                ok = gen_udp:send(Socket, Host, Port, Packet),
                % Increased buffer size for potential large UDP responses
                case gen_udp:recv(Socket, 65535, 1000) of
                    {ok, {_RHost, _RPort, Reply}} when is_binary(Reply) ->
                        {ok, dns:decode_message(Reply)};
                    {error, timeout} ->
                        ?LOG_WARNING("UDP query timed out for ~p", [Message#dns_message.questions]),
                        {error, {timeout, {server, {Host, Port}}}};
                    {error, Error} ->
                        ?LOG_ERROR("UDP recv error: ~p", [Error]),
                        {error, {Error, {server, {Host, Port}}}}
                end
            after
                gen_udp:close(Socket)
            end;
        {error, Reason} ->
            ?LOG_ERROR("Failed to open UDP socket: ~p", [Reason]),
            {error, {socket_error, Reason}}
    end.

% Send the message to the given host:port via TCP.
send_tcp_query(Message, Host, Port) ->
    Packet = dns:encode_message(Message),
    ?LOG_DEBUG("Sending TCP query to host ~p and port ~p", [Host, Port]),
    case gen_tcp:connect(Host, Port, [binary, {packet, 2}, {active, false}], 1000) of
        {ok, Socket} ->
            try
                ok = gen_tcp:send(Socket, Packet),
                case gen_tcp:recv(Socket, 0, 6000) of
                    {ok, Reply} when is_binary(Reply) ->
                        {ok, dns:decode_message(Reply)};
                    {error, timeout} ->
                        ?LOG_WARNING("TCP query timed out for ~p", [Message#dns_message.questions]),
                        {error, {timeout, {server, {Host, Port}}}};
                    {error, closed} ->
                        ?LOG_WARNING("TCP connection closed unexpectedly for ~p", [
                            Message#dns_message.questions
                        ]),
                        {error, {closed, {server, {Host, Port}}}};
                    {error, Error} ->
                        ?LOG_ERROR("TCP recv error: ~p", [Error]),
                        {error, {Error, {server, {Host, Port}}}}
                end
            after
                gen_tcp:close(Socket)
            end;
        {error, Reason} ->
            ?LOG_ERROR("Failed to connect TCP socket: ~p", [Reason]),
            {error, {connect_error, Reason}}
    end.

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
        keytag = Data#dns_rrdata_rrsig.keytag,
        signature = Data#dns_rrdata_rrsig.signature
    }.

update_dnskey(ExpectedRRData, []) ->
    ExpectedRRData;
update_dnskey(ExpectedRRData, [{_, _, _, _, Data} | _]) ->
    ExpectedRRData#dns_rrdata_dnskey{
        keytag = Data#dns_rrdata_dnskey.keytag,
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
