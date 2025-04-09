-module(dnstest_metrics).

-behaviour(gen_server).

% Public API
-export([start_link/0, start/0, run_number/0, insert/2, clear/0, display/0, display/1, slowest/0]).

% Gen server hooks
-export([init/1, handle_call/3, handle_cast/2]).

-define(SERVER, ?MODULE).

-record(state, {
    run_number = 0 :: non_neg_integer(),
    data = [] :: [{dnstest:name(), non_neg_integer()}]
}).
-opaque state() :: #state{}.
-export_type([state/0]).

% Public API
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, noargs, []).

%% Marks the start of a test run. This will increment a counter
%% so that tests run together can be displayed together.
-spec start() -> ok.
start() ->
    gen_server:call(?SERVER, start).

%% Get the current run number.
-spec run_number() -> non_neg_integer().
run_number() ->
    gen_server:call(?SERVER, run_number).

-spec insert(dnstest:name(), non_neg_integer()) -> ok.
insert(Name, Time) ->
    gen_server:cast(?SERVER, {insert, Name, Time}).

-spec clear() -> ok.
clear() ->
    gen_server:cast(?SERVER, clear).

-spec display() -> ok.
display() ->
    gen_server:call(?SERVER, display).

-spec display([dnstest:name()]) -> ok.
display(Names) ->
    gen_server:call(?SERVER, {display, Names}).

-spec slowest() -> ok.
slowest() ->
    gen_server:call(?SERVER, {display, slowest}).

% Gen server functions
-spec init(noargs) -> {ok, state()}.
init(_) ->
    {ok, #state{}}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, term(), state()}.
handle_call(start, _From, State) ->
    {reply, ok, State#state{run_number = State#state.run_number + 1}};
handle_call(run_number, _From, State) ->
    {reply, State#state.run_number, State};
handle_call(display, _From, State) ->
    display_list(State#state.data),
    {reply, ok, State};
handle_call({display, Names}, _From, State) when is_list(Names) ->
    display_list(
        lists:filter(
            fun({Name, _}) ->
                lists:member(atom_to_list(Name), Names)
            end,
            State#state.data
        )
    ),
    {reply, ok, State};
handle_call({display, slowest}, _From, State) ->
    display_list(lists:sort(fun({_, A}, {_, B}) -> A > B end, State#state.data)),
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({insert, Name, Time}, State) ->
    {noreply, State#state{data = [{Name, Time} | State#state.data]}};
handle_cast(clear, State) ->
    {noreply, State#state{data = []}}.

% Internal API

display_list(Results) ->
    io:format("--- Query Times ---~n"),
    lists:foreach(
        fun({Name, T}) ->
            io:format("~p: ~p ms~n", [Name, T / 1000])
        end,
        lists:reverse(Results)
    ).
