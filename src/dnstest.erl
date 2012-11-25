-module(dnstest).

-export([start/0]).

start() ->
  lager:start(),
  application:start(dnstest).

