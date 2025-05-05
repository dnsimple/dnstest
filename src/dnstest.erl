-module(dnstest).

-include_lib("kernel/include/logger.hrl").

-callback definitions() -> [dnstest:definition()].

-export([start/0, stop/0, run/0, run/1]).

-type name() :: atom() | string().
-type response() :: {dns:dname(), dns:class(), dns:type(), dns:ttl(), dns:rrdata()}.
-type definition() :: {
    atom(),
    #{
        question := {string() | binary(), dns:type()},
        additional => [dns:optrr()],
        transport => udp | tcp,
        ignore => [atom()],
        response := #{
            header := dns:message(),
            answers := [response()],
            authority := [response()],
            additional := [response()]
        }
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
    Definitions = load_all_definitions(),
    dnstest_harness:run(Definitions);
run(Names) ->
    dnstest_metrics:start(),
    ?LOG_INFO("Running targeted tests: ~p (#~p)", [Names, dnstest_metrics:run_number()]),
    Definitions = load_all_definitions(),
    dnstest_harness:run(Definitions, Names).

%% @doc Loads all definitions from all configured definition modules
-spec load_all_definitions() -> [definition()].
load_all_definitions() ->
    Modules = definition_modules(),
    ?LOG_INFO("Loading definitions from modules: ~p", [Modules]),
    lists:flatten([M:definitions() || M <- Modules]).

%% @doc Returns the list of modules that contain test definitions
-spec definition_modules() -> [module()].
definition_modules() ->
    % Check if a specific set of modules is configured
    case application:get_env(dnstest, definition_modules) of
        {ok, ConfiguredModules} when is_list(ConfiguredModules) ->
            ConfiguredModules;
        _ ->
            % Fall back to the default module and any modules in the tests directory
            DefaultModule = default_definition_module(),
            SpecModules = discover_spec_modules(),
            [DefaultModule | SpecModules]
    end.

%% @doc Discovers spec modules in the tests directory
-spec discover_spec_modules() -> [module()].
discover_spec_modules() ->
    % Find all *_specs.erl modules in the tests directory
    TestsDir = filename:join(code:lib_dir(dnstest), "src/tests"),
    case file:list_dir(TestsDir) of
        {ok, Files} ->
            [
                list_to_atom(filename:rootname(F))
             || F <- Files,
                filename:extension(F) =:= ".erl",
                string:find(F, "_specs.erl") =/= nomatch
            ];
        {error, _Reason} ->
            []
    end.

%% @doc Returns the default definitions module
-spec default_definition_module() -> module().
default_definition_module() ->
    case application:get_env(dnstest, definitions) of
        {ok, Module} -> Module;
        _ -> dnstest_definitions
    end.
