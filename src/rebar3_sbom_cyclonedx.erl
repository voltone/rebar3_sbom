-module(rebar3_sbom_cyclonedx).

-export([bom/1, bom/2, uuid/0]).

bom(Components) ->
    bom(Components, uuid()).

bom(Components, Serial) ->
    Bom = {bom, [{serialNumber, Serial}, {xmlns, "http://cyclonedx.org/schema/bom/1.1"}], [
        {components, [], [component(Component) || Component <- Components, Component /= undefined]}
    ]},
    xmerl:export_simple([Bom], xmerl_xml).

component(Component) ->
    {component, [{type, "library"}],
        [component_field(Field, Value) || {Field, Value} <- Component, Value /= undefined]}.

component_field(name, Name) -> {name, [], [[Name]]};
component_field(version, Version) -> {version, [], [[Version]]};
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
