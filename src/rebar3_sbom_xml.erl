-module(rebar3_sbom_xml).

-export([encode/1, decode/1]).

-include("rebar3_sbom.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(XMLNS, "http://cyclonedx.org/schema/bom/1.4").
-define(XMLNS_XSI, "http://www.w3.org/2001/XMLSchema-instance").
-define(XSI_SCHEMA_LOC, "http://cyclonedx.org/schema/bom/1.4 https://cyclonedx.org/schema/bom-1.4.xsd").

encode(SBoM) ->
    Content = sbom_to_xml(SBoM),
    xmerl:export_simple([Content], xmerl_xml).

decode(FilePath) ->
    % Note: This sets the SBoM version to 0 if the xml file
    %       does not have a valid version.
    {SBoM, _} = xmerl_scan:file(FilePath),
    Version = xml_to_bom_version(SBoM, 0),
    Components = [
        xml_to_component(C) || C <- xpath("/bom/components/component", SBoM)
    ],
    #sbom{version = Version, components = Components}.

% Encode -----------------------------------------------------------------------
xml_to_bom_version(Xml, Default) ->
    case xpath("/bom/@version", Xml) of
        [Attr] ->
            erlang:list_to_integer(Attr#xmlAttribute.value);
        [] ->
            Default
    end.

sbom_to_xml(#sbom{metadata = Metadata} = SBoM) ->
    {
        bom, [
            {xmlns, ?XMLNS},
            {'xmlns:xsi', ?XMLNS_XSI},
            {'xsi:schemaLocation', ?XSI_SCHEMA_LOC},
            {version, SBoM#sbom.version},
            {serialNumber, SBoM#sbom.serial}
        ],
        [
            {metadata, [
                {timestamp, [Metadata#metadata.timestamp]},
                {tools,
                    [tool_to_xml(Tool) || Tool <- Metadata#metadata.tools]
                }
            ]},
            {components, [component_to_xml(C) || C <- SBoM#sbom.components]},
            {dependencies, [dependency_to_xml(D) || D <- SBoM#sbom.dependencies]}
        ]
    }.

tool_to_xml(Tool) ->
    {tool, [{name, [Tool]}]}.

component_to_xml(C) ->
    Attributes = [{type, C#component.type}, {'bom-ref', C#component.bom_ref}],
    Content = prune_content([
        component_field_to_xml(author, C#component.author),
        component_field_to_xml(name, C#component.name),
        component_field_to_xml(version, C#component.version),
        component_field_to_xml(description, C#component.description),
        component_field_to_xml(hashes, C#component.hashes),
        component_field_to_xml(licenses, C#component.licenses),
        component_field_to_xml(purl, C#component.purl)
    ]),
    {component, Attributes, Content}.

prune_content(Content) ->
    lists:filter(fun(Field) -> Field =/= undefined end, Content).

component_field_to_xml(_, undefined) ->
    undefined;
component_field_to_xml(hashes, Hashes) ->
    {hashes, [hash_to_xml(Hash) || Hash <- Hashes]};
component_field_to_xml(licenses, Licenses) ->
    {licenses, [license_to_xml(License) || License <- Licenses]};
component_field_to_xml(FieldName, Value) ->
    {FieldName, [Value]}.

hash_to_xml(#{alg := Alg, hash := Hash}) ->
    {hash, [{alg, Alg}], [Hash]}.

license_to_xml(#{name := Name}) ->
    {license, [{name, [Name]}]};
license_to_xml(#{id := Id}) ->
    {license, [{id, [Id]}]}.

dependency_to_xml(Dependency) ->
    {dependency, [{ref, Dependency#dependency.ref}],
        [dependency_to_xml(D) || D <- Dependency#dependency.dependencies]
    }.

% Decode -----------------------------------------------------------------------
xml_to_component(Component) ->
    [#xmlAttribute{value = Type}] = xpath("/component/@type", Component),
    [#xmlAttribute{value = BomRef}] = xpath("/component/@bom-ref", Component),
    Author = xpath("/component/author/text()", Component),
    Name = xpath("/component/name/text()", Component),
    Version = xpath("/component/version/text()", Component),
    Description = xpath("/component/description/text()", Component),
    Purl = xpath("/component/purl/text()", Component),
    Hashes = [
        xml_to_hash(H) || H <- xpath("/component/hashes/hash", Component)
    ],
    Licenses = [
        xml_to_license(L) || L <- xpath("/component/licenses/license", Component)
    ],
    #component{
        type = Type,
        bom_ref = BomRef,
        author = xml_to_component_field(Author),
        name = xml_to_component_field(Name),
        version = xml_to_component_field(Version),
        description = xml_to_component_field(Description),
        purl = xml_to_component_field(Purl),
        hashes = Hashes,
        licenses = Licenses
    }.

xml_to_component_field([]) ->
    undefined;
xml_to_component_field([#xmlText{value = Value}]) ->
    Value.

xml_to_hash(HashElement) ->
    [#xmlText{value = Hash}] = xpath("/hash/text()", HashElement),
    [#xmlAttribute{value = Alg}] = xpath("/hash/@alg", HashElement),
    #{hash => Hash, alg => Alg}.

xml_to_license(LicenseElement) ->
    case xpath("/license/id/text()", LicenseElement) of
        [Value] ->
            #{id => Value#xmlText.value};
        [] ->
            [Value] = xpath("/license/name/text()", LicenseElement),
            #{name => Value#xmlText.value}
    end.

xpath(String, Xml) ->
    xmerl_xpath:string(String, Xml).
