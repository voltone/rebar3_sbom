-module(rebar3_sbom).

-export([init/1]).

-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    {ok, State1} = rebar3_sbom_prv:init(State),
    {ok, State1}.
