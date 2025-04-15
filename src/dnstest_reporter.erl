-module(dnstest_reporter).
-include_lib("kernel/include/logger.hrl").

-export([report/1, validate/1]).

-spec report([dnstest_harness:return()]) -> ok.
report(TestResults) ->
    {Pass, Fail} = lists:partition(fun(#{result := Result}) -> true =:= Result end, TestResults),
    lists:foreach(fun(Return) -> ?LOG_INFO(Return) end, Fail),
    ?LOG_INFO(#{
        passed_num => length(Pass),
        failed_num => length(Fail)
    }).

-spec validate([dnstest_harness:return()]) -> no_return().
validate(TestResults) ->
    case lists:all(fun(#{result := Result}) -> true =:= Result end, TestResults) of
        true ->
            halt(0);
        false ->
            halt(1)
    end.
