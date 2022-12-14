-module(rebar3_sbom_cyclonedx).

-export([bom/3, bom/4, uuid/0]).

-define(APP, "rebar3_sbom").
-define(DEFAULT_VERSION, "1").
-define(COMPONENT_FIELDS, [name, version, author, description, licenses, purl, sha256]).

-include_lib("xmerl/include/xmerl.hrl").

bom(File, Components, Opts) ->
    bom(File, Components, Opts, uuid()).

bom(File, Components, Opts, Serial) ->
    ValidComponents = lists:filter(fun(E) -> E =/= undefined end, Components),
    Content = {bom, [{version, ?DEFAULT_VERSION},
                     {serialNumber, Serial},
                     {xmlns, "http://cyclonedx.org/schema/bom/1.4"}],
               [{metadata, metadata()},
                {components, [], [component(Component) || Component <- ValidComponents]},
                {dependencies, [], [dependency(Component) || Component <- ValidComponents]}]},
    Normalized = xmerl_lib:normalize_element(Content),
    Bom = update_version(File, Normalized, Opts),
    xmerl:export_simple([Bom], xmerl_xml).

metadata() ->
    [{timestamp, [calendar:system_time_to_rfc3339(erlang:system_time(second))]},
     {tools, [{tool, [{name, [?APP]}]}]}
    ].

component(Component) ->
    {component, [{type, "library"}, {'bom-ref', bom_ref_of_component(Component)}],
        [component_field(Field, Value)
         || {Field, Value} <- Component,
            lists:member(Field, ?COMPONENT_FIELDS), Value /= undefined, Value /= []]}.

component_field(name, Name) -> {name, [], [[Name]]};
component_field(version, Version) -> {version, [], [[Version]]};
component_field(author, Author) -> {author, [], [[string:join(Author, ",")]]};
component_field(description, Description) -> {description, [], [[Description]]};
component_field(licenses, Licenses) -> {licenses, [], [license(License) || License <- Licenses]};
component_field(purl, Purl) -> {purl, [], [[Purl]]};
component_field(sha256, Sha256) ->
    {hashes, [], [
        {hash, [{alg, "SHA-256"}], [[Sha256]]}
    ]}.

license(Name) ->
    case rebar3_sbom_license:spdx_id(Name) of
        undefined ->
            {license, [], [{name, [], [[Name]]}]};
        SpdxId ->
            {license, [], [{id, [], [[SpdxId]]}]}
    end.

uuid() ->
    [A, B, C, D, E] = [crypto:strong_rand_bytes(Len) || Len <- [4, 2, 2, 2, 6]],
    lists:join("-", [hex(Part) || Part <- [A, B, <<4:4, C:12/binary-unit:1>>, <<2:2, D:14/binary-unit:1>>, E]]).

hex(Bin) ->
    string:lowercase(<< <<Hex>> || <<Nibble:4>> <= Bin, Hex <- integer_to_list(Nibble,16) >>).

update_version(File, #xmlElement{attributes = Attrs} = Bom, Opts) ->
    Version = get_version(File, Bom, Opts),
    Attr = lists:keyfind(version, #xmlAttribute.name, Attrs),
    NewAttr = Attr#xmlAttribute{value = Version},
    NewAttrs = lists:keyreplace(version, #xmlAttribute.name, Attrs, NewAttr),
    Bom#xmlElement{attributes = NewAttrs}.

get_version(File, Bom, Opts) ->
    try
        case xmerl_scan:file(File) of
            {#xmlElement{attributes = Attrs} = Old, _} ->
                case lists:keyfind(version, #xmlAttribute.name, Attrs) of
                    false ->
                        ?DEFAULT_VERSION;
                    #xmlAttribute{value = Value} ->
                        case is_strict_version(Opts) andalso is_bom_equal(Old, Bom) of
                            true ->
                                Value;
                            _ ->
                                Version = erlang:list_to_integer(Value),
                                erlang:integer_to_list(Version + 1)
                        end
                end;
            {error, enoent} ->
                ?DEFAULT_VERSION
        end
    catch _:Reason ->
            logger:error("scan file:~ts failed, reason:~p, will use the default version number 1",
                         [File, Reason]),
            ?DEFAULT_VERSION
    end.

is_strict_version(Opts) ->
    proplists:get_value(strict_version, Opts, true).

is_bom_equal(#xmlElement{content = A}, #xmlElement{content = B}) ->
    lists:all(fun(Key) ->
                      ValA = lists:keyfind(Key, #xmlElement.name, A),
                      ValB = lists:keyfind(Key, #xmlElement.name, B),
                      case {ValA, ValB} of
                          {false, false} -> true;
                          {false, _} -> false;
                          {_, false} -> false;
                          {_, _} ->
                              xmerl_lib:simplify_element(ValA) =:=
                                  xmerl_lib:simplify_element(ValB)
                      end
              end,
              [components]).

dependency(Component) ->
    Ref = bom_ref_of_component(Component),
    Deps = proplists:get_value(dependencies, Component, []),
    {dependency, [{ref, [Ref]}], [dependency([{name, Dep}]) || Dep <- Deps]}.

bom_ref_of_component(Component) ->
    Name = proplists:get_value(name, Component),
    lists:flatten(io_lib:format("ref_component_~ts", [Name])).
