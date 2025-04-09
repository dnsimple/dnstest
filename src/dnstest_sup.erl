-module(dnstest_sup).
-behaviour(supervisor).
-include_lib("kernel/include/logger.hrl").

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Public API
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, noargs).

-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(_) ->
    Strategy = #{strategy => one_for_one, intensity => 5, period => 10},
    ?LOG_INFO("Supervisor is starting procs"),
    Procs = [
        #{
            id => dnstest_harness,
            start => {dnstest_harness, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [dnstest_harness]
        },
        #{
            id => dnstest_metrics,
            start => {dnstest_metrics, start_link, []},
            restart => permanent,
            shutdown => 5000,
            type => worker,
            modules => [dnstest_metrics]
        }
    ],
    {ok, {Strategy, Procs}}.
