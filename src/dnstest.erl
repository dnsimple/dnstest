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
  lager:info("Running all tests"),
  gen_server:cast(dnstest_harness, {run, dnstest_definitions:definitions()});
run(Names) ->
  lager:info("Running targeted tests: ~p", [Names]),
  gen_server:cast(dnstest_harness, {run_target, dnstest_definitions:definitions(), Names}).
