-module(rebar3_sbom_json).

-export([encode/1, decode/1]).

-include("rebar3_sbom.hrl").

-define(SPEC_VERSION, <<"1.4">>).
-define(SCHEMA, <<"http://cyclonedx.org/schema/bom-1.4.schema.json">>).

encode(SBoM) ->
    Content = sbom_to_json(SBoM),
    jsone:encode(Content, [native_forward_slash, native_utf8, canonical_form]).

decode(FilePath) ->
    % Note: This sets the SBoM version to 0 if the json file
    %       does not have a valid version.
    {ok, File} = file:read_file(FilePath),
    JsonTerm = jsone:decode(File),
    Version = maps:get(<<"version">>, JsonTerm, 0),
    Components = json_to_components(maps:get(<<"components">>, JsonTerm, [])),
    #sbom{version = Version, components = Components}.

% Encode -----------------------------------------------------------------------
sbom_to_json(#sbom{metadata = Metadata} = SBoM) ->
    #{
        '$schema' => ?SCHEMA,
        bomFormat => bin(SBoM#sbom.format),
        specVersion => ?SPEC_VERSION,
        serialNumber => bin(SBoM#sbom.serial),
        version => SBoM#sbom.version,
        metadata => #{
            timestamp => bin(Metadata#metadata.timestamp),
            tools => [#{name => bin(T)} || T <- Metadata#metadata.tools]
        },
        components => [component_to_json(C) || C <- SBoM#sbom.components],
        dependencies => [dependency_to_json(D) || D <- SBoM#sbom.dependencies]
    }.

component_to_json(C) ->
    prune_content(#{
        type => bin(C#component.type),
        'bom-ref' => bin(C#component.bom_ref),
        author => bin(C#component.author),
        name => bin(C#component.name),
        version => bin(C#component.version),
        description => bin(C#component.description),
        hashes => hashes_to_json(C#component.hashes),
        licenses => licenses_to_json(C#component.licenses),
        purl => bin(C#component.purl)
    }).

prune_content(Component) ->
    maps:filter(fun(_, Value) -> Value =/= undefined end, Component).

hashes_to_json(undefined) ->
    undefined;
hashes_to_json(Hashes) ->
    [hash_to_json(H) || H <- Hashes].

hash_to_json(#{alg := Alg, hash := Hash}) ->
    #{alg => bin(Alg), content => bin(Hash)}.

licenses_to_json(undefined) ->
    undefined;
licenses_to_json(Licenses) ->
    [license_to_json(L) || L <- Licenses].

license_to_json(#{name := Name}) ->
    #{license => #{name => bin(Name)}};
license_to_json(#{id := Id}) ->
    #{license => #{id => bin(Id)}}.

dependency_to_json(D) ->
    #{
        ref => bin(D#dependency.ref),
        dependsOn => [
            bin(SubD#dependency.ref) || SubD <- D#dependency.dependencies
        ]
    }.

bin(undefined) ->
    undefined;
bin(Value) when is_list(Value) ->
    erlang:list_to_binary(Value);
bin(Value) ->
    Value.

% Decode -----------------------------------------------------------------------
json_to_components(Components) when is_list(Components) ->
    lists:map(fun json_to_components/1, Components);
json_to_components(C) ->
    #component{
        bom_ref = json_to_component_field(<<"bom-ref">>, C),
        author = json_to_component_field(<<"author">>, C),
        description = json_to_component_field(<<"description">>, C),
        hashes = json_to_component_field(<<"hashes">>, C),
        licenses = json_to_component_field(<<"licenses">>, C),
        name = json_to_component_field(<<"name">>, C),
        purl = json_to_component_field(<<"purl">>, C),
        type = json_to_component_field(<<"type">>, C),
        version = json_to_component_field(<<"version">>, C)
    }.

json_to_component_field(<<"hashes">> = F, Component) ->
    json_to_hashes(maps:get(F, Component, undefined));
json_to_component_field(<<"licenses">> = F, Component) ->
    json_to_licenses(maps:get(F, Component, undefined));
json_to_component_field(FieldName, Component) ->
    str(maps:get(FieldName, Component, undefined)).

json_to_hashes(undefined) ->
    undefined;
json_to_hashes(Hashes) ->
    [json_to_hash(H) || H <- Hashes].

json_to_hash(#{<<"alg">> := Alg, <<"content">> := Content}) ->
    #{alg => str(Alg), hash => str(Content)}.

json_to_licenses(undefined) ->
    undefined;
json_to_licenses(Licenses) ->
    [json_to_license(L) || L <- Licenses].

json_to_license(#{<<"license">> := #{<<"id">> := Id}}) ->
    #{id => str(Id)};
json_to_license(#{<<"license">> := #{<<"name">> := Name}}) ->
    #{name => str(Name)}.


str(undefined) ->
    undefined;
str(Value) when is_binary(Value) ->
    erlang:binary_to_list(Value);
str(Value) ->
    Value.
