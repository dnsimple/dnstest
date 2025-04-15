-module(dnstest).

-include_lib("kernel/include/logger.hrl").

-callback definitions() -> [dnstest:definition()].

-export([start/0, stop/0, run/0, run/1]).

-type name() :: atom() | string().
-type definition() :: {
    atom(),
    #{
        question := _,
        header := _,
        records := #{answers := _, authority := _, additional := _},
        additional => _
    }
}.
-export_type([name/0, definition/0]).

-spec start() -> no_return().
start() ->
    {ok, _} = application:ensure_all_started(dnstest),
    Args = init:get_plain_arguments(),
    TestResults = run(Args),
    dnstest_reporter:validate(TestResults).

-spec stop() -> ok | {error, term()}.
stop() ->
    application:stop(dnstest).

-spec run() -> [dnstest_harness:return()].
run() ->
    run([]).

-spec run([string()]) -> [dnstest_harness:return()].
run([]) ->
    dnstest_metrics:start(),
    ?LOG_INFO("Running all tests (#~p)", [dnstest_metrics:run_number()]),
    DefinitionsModule = definitions_module(),
    dnstest_harness:run(DefinitionsModule:definitions());
run(Names) ->
    dnstest_metrics:start(),
    ?LOG_INFO("Running targeted tests: ~p (#~p)", [Names, dnstest_metrics:run_number()]),
    DefinitionsModule = definitions_module(),
    dnstest_harness:run(DefinitionsModule:definitions(), Names).

definitions_module() ->
    case application:get_env(dnstest, definitions) of
        {ok, Module} -> Module;
        _ -> dnstest_definitions
    end.
