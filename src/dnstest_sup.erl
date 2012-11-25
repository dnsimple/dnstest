-module(dnstest_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Public API
start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

init(_Args) ->
  lager:info("Supervisor is starting procs"),
  Procs = [
    {dnstest_harness, {dnstest_harness, start_link, []}, permanent, 5000, worker, [dnstest_harness]}
  ],
  {ok, {{one_for_one, 5, 10}, Procs}}.
