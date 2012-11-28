-module(dnstest_reporter).

-export([report/1]).

report(TestResults) ->
  PassFail = lists:map(
    fun({Name, Result}) ->
        [Name, lists:all(fun(R) -> R end, Result)]
    end, TestResults),
  {Pass, Fail} = lists:partition(fun([_, Result]) -> Result end, PassFail),
  lager:info("~p Passed, ~p Failed", [length(Pass), length(Fail)]),
  lists:foreach(fun(R) -> lager:info("~p: ~p", R) end, Fail).
