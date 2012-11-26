-module(dnstest).

-export([start/0]).

start() ->
  lager:start(),
  application:start(dnstest),
  run().

run() ->
  TestResults = gen_server:call(dnstest_harness, {run, dnstest_definitions:definitions()}),
  PassFail = lists:map(
    fun({Name, Result}) ->
        [Name, lists:all(fun(R) -> R end, Result)]
    end, TestResults),
  {Pass, Fail} = lists:partition(fun([_, Result]) -> Result end, PassFail),
  lager:info("~p Passed, ~p Failed", [length(Pass), length(Fail)]),
  lists:foreach(fun(R) -> lager:info("~p: ~p", R) end, Fail).
