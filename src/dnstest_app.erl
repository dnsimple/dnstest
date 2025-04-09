-module(dnstest_app).
-behaviour(application).
-include_lib("kernel/include/logger.hrl").

% Application hooks
-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> supervisor:startlink_ret() | {error, no_api_key}.
start(Type, Args) ->
    ?LOG_INFO("~p:start(~p, ~p)", [?MODULE, Type, Args]),
    dnstest_sup:start_link().

-spec stop(_) -> ok.
stop(State) ->
    ?LOG_INFO("~p:stop(~p)~n", [?MODULE, State]),
    ok.
