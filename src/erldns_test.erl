-module(erldns_test).

-export([start/0]).

start() ->
  lager:start(),
  application:start(erldns_test).

