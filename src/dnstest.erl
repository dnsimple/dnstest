-module(dnstest).

-export([start/0, stop/0, run/0, run/1]).

start() ->
  lager:start(),
  application:start(dnstest),
  case init:get_plain_arguments() of
    [] -> run([]);
    Names -> run(Names)
  end.

stop() ->
  application:stop(dnstest).

run() -> run([]).

run(Name) when is_atom(Name) ->
  run([atom_to_list(Name)]);
run([]) ->
  dnstest_metrics:start(),
  lager:info("Running all tests (#~p)", [dnstest_metrics:run_number()]),
  DefinitionsModule = definitions_module(),
  gen_server:cast(dnstest_harness, {run, DefinitionsModule:definitions()});
run(Names) ->
  dnstest_metrics:start(),
  lager:info("Running targeted tests: ~p (#~p)", [Names, dnstest_metrics:run_number()]),
  DefinitionsModule = definitions_module(),
  gen_server:cast(dnstest_harness, {run_target, DefinitionsModule:definitions(), Names}).

definitions_module() ->
  case application:get_env(dnstest, definitions) of
    {ok, Module} -> Module;
    _ -> dnstest_definitions
  end.
