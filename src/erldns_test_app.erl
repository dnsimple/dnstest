-module(erldns_test_app).
-behavior(application).

% Application hooks
-export([start/2, stop/1]).

start(Type, Args) ->
  lager:info("~p:start(~p, ~p)", [?MODULE, Type, Args]),
  random:seed(erlang:now()),
  erldns_test_sup:start_link().

stop(State) ->
  lager:info("~p:stop(~p)~n", [?MODULE, State]),
  ok.
