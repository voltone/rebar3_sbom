-module(rebar3_sbom_cyclonedx).

-export([bom/3, bom/4, uuid/0]).

-include("rebar3_sbom.hrl").

bom(FileInfo, IsStrictVersion, RawComponents) ->
    bom(FileInfo, IsStrictVersion, RawComponents, uuid()).

bom({FilePath, _} = FileInfo, IsStrictVersion, RawComponents, Serial) ->
    ValidRawComponents = lists:filter(fun(E) -> E =/= undefined end, RawComponents),
    SBoM = #sbom{
        serial = Serial,
        metadata = metadata(),
        components = components(ValidRawComponents),
        dependencies = dependencies(ValidRawComponents)
    },
    try
        V = version(FileInfo, IsStrictVersion, SBoM),
        SBoM#sbom{version = V}
    catch _:Reason ->
        logger:error("scan file:~ts failed, reason:~p, will use the default version number ~p",
                     [FilePath, Reason, ?DEFAULT_VERSION]),
        SBoM
    end.

metadata() ->
    #metadata{
        timestamp = calendar:system_time_to_rfc3339(erlang:system_time(second)),
        tools = [?APP]
    }.

components(RawComponents) ->
    [component(RawComponent) || RawComponent <- RawComponents].

component(RawComponent) ->
    #component{
        bom_ref = bom_ref_of_component(RawComponent),
        name = component_field(name, RawComponent),
        author = component_field(author, RawComponent),
        version = component_field(version, RawComponent),
        description = component_field(description, RawComponent),
        hashes = component_field(sha256, RawComponent),
        licenses = component_field(licenses, RawComponent),
        purl = component_field(purl, RawComponent)
    }.

component_field(author = Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        undefined ->
            undefined;
        Value ->
            string:join(Value, ",")
    end;
component_field(licenses = Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        undefined ->
            undefined;
        Licenses ->
            [license(License) || License <- Licenses]
    end;
component_field(sha256 = Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        undefined ->
            undefined;
        Hash ->
            [#{alg => "SHA-256", hash => binary:bin_to_list(Hash)}]
    end;
component_field(Field, RawComponent) ->
    case proplists:get_value(Field, RawComponent) of
        Value when is_binary(Value) ->
            binary:bin_to_list(Value);
        Else ->
            Else
    end.

license(Name) ->
    case rebar3_sbom_license:spdx_id(Name) of
        undefined ->
            #{name => Name};
        SpdxId ->
            #{id => SpdxId}
    end.

uuid() ->
    [A, B, C, D, E] = [crypto:strong_rand_bytes(Len) || Len <- [4, 2, 2, 2, 6]],
    UUID = lists:join("-", [hex(Part) || Part <- [A, B, <<4:4, C:12/binary-unit:1>>, <<2:2, D:14/binary-unit:1>>, E]]),
    "urn:uuid:" ++ UUID.

hex(Bin) ->
    string:lowercase(<< <<Hex>> || <<Nibble:4>> <= Bin, Hex <- integer_to_list(Nibble,16) >>).

dependencies(undefined) ->
    [];
dependencies(RawComponents) ->
    [dependency(RawComponent) || RawComponent <- RawComponents].

dependency(RawComponent) ->
    RawDependencies = proplists:get_value(dependencies, RawComponent, []),
    #dependency{
        ref = bom_ref_of_component(RawComponent),
        dependencies = [
            dependency([{name, D}]) || D <- RawDependencies
        ]
    }.

bom_ref_of_component(RawComponent) ->
    Name = proplists:get_value(name, RawComponent),
    lists:flatten(io_lib:format("ref_component_~ts", [Name])).

version({FilePath, Format}, IsStrictVersion, NewSBoM) ->
    case filelib:is_regular(FilePath) of
        true ->
            OldSBoM = decode(FilePath, Format),
            version(IsStrictVersion, {NewSBoM, OldSBoM});
        false ->
            rebar_api:info(
                "Using default SBoM version ~p: no previous SBoM file found.",
                [?DEFAULT_VERSION]
            ),
            ?DEFAULT_VERSION
    end.

-spec version(IsStrictVersion, {NewSBoM, OldSBoM}) -> Version when
    IsStrictVersion :: boolean(),
    NewSBoM :: #sbom{}, OldSBoM :: #sbom{},
    Version :: integer().
version(_, {_, OldSBoM}) when OldSBoM#sbom.version =:= 0 ->
    rebar_api:info(
        "Using default SBoM version ~p: invalid version in previous SBoM file.",
        [?DEFAULT_VERSION]
    ),
    ?DEFAULT_VERSION;
version(IsStrictVersion, {_, OldSBoM}) when IsStrictVersion =:= false ->
    rebar_api:info(
        "Incrementing the SBoM version unconditionally: strict_version is set to false.", []
    ),
    OldSBoM#sbom.version + 1;
version(IsStrictVersion, {NewSBoM, OldSBoM}) when IsStrictVersion =:= true ->
    case is_sbom_equal(NewSBoM, OldSBoM) of
        true ->
            rebar_api:info(
                "Not incrementing the SBoM version: new SBoM is equivalent to the old SBoM.", []
            ),
            OldSBoM#sbom.version;
        false ->
            rebar_api:info(
                "Incrementing the SBoM version: new SBoM is not equivalent to the old SBoM.", []
            ),
            OldSBoM#sbom.version + 1
    end.

is_sbom_equal(#sbom{components = NewComponents}, #sbom{components = OldComponents}) ->
    lists:all(fun(C) -> lists:member(C, NewComponents) end, OldComponents)
    andalso
    lists:all(fun(C) -> lists:member(C, OldComponents) end, NewComponents).

decode(FilePath, "xml") ->
    rebar3_sbom_xml:decode(FilePath);
decode(FilePath, "json") ->
    rebar3_sbom_json:decode(FilePath).
