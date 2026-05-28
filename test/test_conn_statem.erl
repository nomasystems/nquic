%%%-------------------------------------------------------------------
%%% Minimal gen_statem fixture for listener / dispatch tests that
%%% need a real gen_statem-speaking process to receive shutdown
%%% requests (`nquic_conn:close', `gen_statem:stop'). Lives in
%%% `test/' so it never ships with the production build.
%%%-------------------------------------------------------------------
-module(test_conn_statem).

-behaviour(gen_statem).

-export([start/0, start_link/0]).
-export([init/1, callback_mode/0, terminate/3]).
-export([idle/3]).

start() ->
    gen_statem:start(?MODULE, [], []).

start_link() ->
    gen_statem:start_link(?MODULE, [], []).

callback_mode() ->
    state_functions.

init(_) ->
    {ok, idle, undefined}.

idle({call, From}, _Request, Data) ->
    {keep_state, Data, [{reply, From, ok}]};
idle(cast, _Msg, Data) ->
    {keep_state, Data};
idle(info, _Msg, Data) ->
    {keep_state, Data}.

terminate(_Reason, _State, _Data) ->
    ok.
