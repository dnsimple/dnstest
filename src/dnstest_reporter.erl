-module(dnstest_reporter).
-include_lib("kernel/include/logger.hrl").

-export([report/1]).

-spec report([dnstest_harness:return()]) -> ok.
report(TestResults) ->
    {Pass, Fail} = lists:partition(fun(#{result := Result}) -> true =:= Result end, TestResults),
    ?LOG_INFO(#{passed_num => length(Pass), passed => lists:map(fun(#{name := Name}) -> Name end, Pass),
                failed_num => length(Fail), failed => lists:map(fun(#{name := Name}) -> Name end, Fail)}),
    lists:foreach(fun(Return) -> ?LOG_INFO(Return) end, Fail).
