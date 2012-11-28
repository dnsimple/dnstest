-module(dnstest).

-export([start/0, stop/0]).

start() ->
  lager:start(),
  application:start(dnstest),
  run().

stop() ->
  application:stop(dnstest).

run() ->
  case init:get_plain_arguments() of
    [] ->
      gen_server:cast(dnstest_harness, {run, dnstest_definitions:definitions()});
    Names ->
      lager:info("Running targeted tests: ~p", [Names]),
      gen_server:cast(dnstest_harness, {run_target, dnstest_definitions:definitions(), Names})
  end.
