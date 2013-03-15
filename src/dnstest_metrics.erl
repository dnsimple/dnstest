-module(dnstest_metrics).

-behavior(gen_server).

% Public API
-export([start_link/0, start/0, run_number/0, insert/2, clear/0, display/0, display/1, slowest/0]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).

-record(state, {run_number = 0, data=[]}).

% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Marks the start of a test run. This will increment a counter
%% so that tests run together can be displayed together.
start() ->
  gen_server:call(?SERVER, {start}).

%% Get the current run number.
run_number() ->
  gen_server:call(?SERVER, {run_number}).

insert(Name, Time) ->
  gen_server:cast(?SERVER, {insert, Name, Time}).

clear() ->
  gen_server:cast(?SERVER, {clear}).

display() ->
  gen_server:call(?SERVER, {display}).
display(Names) ->
  gen_server:call(?SERVER, {display, Names}).

slowest() ->
  gen_server:call(?SERVER, {display, slowest}).

% Gen server functions
init(_) ->
  {ok, #state{}}.

handle_call({start}, _From, State) ->
  {reply, ok, State#state{run_number = State#state.run_number + 1}};

handle_call({run_number}, _From, State) ->
  {reply, State#state.run_number, State};

handle_call({insert, Name, Time}, _From, State) -> 
  {reply, ok, State#state{data = State#state.data ++ [{Name, Time}]}};

handle_call({display}, _From, State) ->
  display_list(State#state.data),
  {reply, ok, State};

handle_call({display, Names}, _From, State) when is_list(Names) ->
  display_list(lists:filter(
      fun({Name, _}) -> 
          lists:member(atom_to_list(Name), Names) 
      end, State#state.data)),
  {reply, ok, State};

handle_call({display, slowest}, _From, State) ->
  display_list(lists:sort(fun({_, A}, {_, B}) -> A > B end, State#state.data)),
  {reply, ok, State}.


handle_cast({insert, Name, Time}, State) ->
  {noreply, State#state{data = State#state.data ++ [{Name, Time}]}};
handle_cast({clear}, State) ->
  {noreply, State#state{data = []}};
handle_cast({display}, State) ->
  display_list(State#state.data),
  {noreply, State};
handle_cast({display, Names}, State) when is_list(Names) ->
  display_list(lists:filter(fun({Name, _}) -> lists:member(Name, Names) end, State#state.data)),
  {reply, ok, State};
handle_cast({display, slowest}, State) ->
  Sorted = lists:sort(fun({_, A}, {_, B}) -> A > B end, State#state.data),
  display_list(Sorted),
  {noreply, State}.


handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

% Internal API

display_list(Results) -> 
  io:format("--- Query Times ---~n"),
  lists:foreach(fun({Name, T}) ->
        io:format("~p: ~p ms~n", [Name, T / 1000])
    end, Results).

