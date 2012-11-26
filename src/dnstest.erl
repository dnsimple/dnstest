-module(dnstest).

-export([start/0]).

start() ->
  lager:start(),
  application:start(dnstest),
  run().

run() ->
  TestResults = gen_server:call(dnstest_harness, {run, dnstest_definitions:definitions()}),
  lager:info("Test results: ~p", [TestResults]).
