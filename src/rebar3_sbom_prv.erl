-module(rebar3_sbom_prv).

-export([init/1, do/1, format_error/1]).

-define(PROVIDER, sbom).
-define(DEPS, [lock]).

-define(OUTPUT, "bom.xml").

%% ===================================================================
%% Public API
%% ===================================================================
-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    Provider = providers:create([
            {name, ?PROVIDER},            % The 'user friendly' name of the task
            {module, ?MODULE},            % The module implementation of the task
            {bare, true},                 % The task can be run by the user, always true
            {deps, ?DEPS},                % The list of dependencies
            {example, "rebar3 sbom"},     % How to use the plugin
            {opts, [                      % list of options understood by the plugin
              {output, $o, "output", {string, ?OUTPUT}, "the full path to the SBoM output file"},
              {force, $f, "force", {boolean, false}, "overwite existing files without prompting for confirmation"},
              {strict_version, $V, "strict_version", {boolean, true}, "modify the version number of the bom only when the content changes"}
            ]},
            {short_desc, "Generates CycloneDX SBoM"},
            {desc, "Generates a Software Bill-of-Materials (SBoM) in CycloneDX format"}
    ]),
    {ok, rebar_state:add_provider(State, Provider)}.

-spec do(rebar_state:t()) -> {ok, rebar_state:t()} | {error, string()}.
do(State) ->
    {Args, _} = rebar_state:command_parsed_args(State),
    Output = proplists:get_value(output, Args),
    Force = proplists:get_value(force, Args),
    Deps = rebar_state:all_deps(State),
    DepsInfo = [dep_info(Dep) || Dep <- Deps],
    Xml = rebar3_sbom_cyclonedx:bom(Output, DepsInfo, Args),
    case write_file(Output, Xml, Force) of
        ok ->
            rebar_api:info("CycloneDX SBoM written to ~s", [Output]),
            {ok, State};
        {error, Message} ->
            {error, {?MODULE, Message}}
    end.

-spec format_error(any()) ->  iolist().
format_error(Message) ->
    io_lib:format("~s", [Message]).

dep_info(Dep) ->
    Name = rebar_app_info:name(Dep),
    Version = rebar_app_info:original_vsn(Dep),
    Source = rebar_app_info:source(Dep),
    Dir = rebar_app_info:dir(Dep),
    Details = rebar_app_info:app_details(Dep),
    Deps = rebar_app_info:deps(Dep),
    dep_info(Name, Version, Source, Dir, Details, Deps).

dep_info(_Name, _Version, {pkg, Name, Version, Sha256}, _Dir, Details, Deps) ->
    [
        {name, Name},
        {version, Version},
        {author, proplists:get_value(maintainers, Details)},
        {description, proplists:get_value(description, Details)},
        {licenses, proplists:get_value(licenses, Details)},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(Sha256)},
        {dependencies, Deps}
    ];

dep_info(_Name, _Version, {pkg, Name, Version, _InnerChecksum, OuterChecksum, _RepoConfig}, _Dir, Details, Deps) ->
    [
        {name, Name},
        {version, Version},
        {author, proplists:get_value(maintainers, Details)},
        {description, proplists:get_value(description, Details)},
        {licenses, proplists:get_value(licenses, Details)},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(OuterChecksum)},
        {dependencies, Deps}
    ];

dep_info(Name, _Version, {git, Git, {tag, Tag}}, _Dir, Details, Deps) ->
    [
        {name, Name},
        {version, Tag},
        {author, proplists:get_value(maintainers, Details)},
        {description, proplists:get_value(description, Details)},
        {licenses, proplists:get_value(licenses, Details)},
        {purl, rebar3_sbom_purl:git(Name, Git, Tag)},
        {dependencies, Deps}
    ];

dep_info(Name, Version, {git, Git, {ref, Ref}}, _Dir, Details, Deps) ->
    [
        {name, Name},
        {version, Version},
        {author, proplists:get_value(maintainers, Details)},
        {description, proplists:get_value(description, Details)},
        {licenses, proplists:get_value(licenses, Details)},
        {purl, rebar3_sbom_purl:git(Name, Git, Ref)},
        {dependencies, Deps}
    ];

dep_info(_Name, _Version, _Source, _Dir, _Details, _Deps) ->
    undefined.

write_file(Filename, Xml, true) ->
    file:write_file(Filename, Xml);

write_file(Filename, Xml, false) ->
    case file:read_file_info(Filename) of
        {error, enoent} ->
            write_file(Filename, Xml, true);
        {ok, _FileInfo} ->
            Prompt = io_lib:format("File ~s exists; overwrite? [Y/N] ", [Filename]),
            case io:get_line(Prompt) of
                "y\n" -> write_file(Filename, Xml, true);
                "Y\n" -> write_file(Filename, Xml, true);
                _ -> {error, "Aborted"}
            end;
        Error ->
            Error
    end.
