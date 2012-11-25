-module(dnstest_harness).
-behavior(gen_server).

% API
-export([start_link/0]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-record(state, {}).

-define(SERVER, ?MODULE).

% Public API

%% Start the gen server.
start_link() ->
  lager:info("Starting ~p process", [?MODULE]),
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
  {ok, #state{}}.

handle_call(Message, _From, State) ->
  lager:info("handle_call(~p)", [Message]),
  {reply, ok, State}.

handle_cast(Message, State) ->
  lager:info("handle_cast(~p)", [Message]),
  {noreply, State}.

handle_info(Message, State) ->
  lager:info("handle_info(~p)", [Message]),
  {noreply, State}.

terminate(Reason, _State) ->
  lager:info("terminate(~p)", [Reason]),
  ok.

code_change(PreviousVersion, State, Extra) ->
  lager:info("code_change(~p, ~p)", [PreviousVersion, Extra]),
  {ok, State}.
