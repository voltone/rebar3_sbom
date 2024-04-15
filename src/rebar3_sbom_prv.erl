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
    Details = rebar_app_info:app_details(Dep),
    Deps = rebar_app_info:deps(Dep),
    Common =
        [
         {author, proplists:get_value(maintainers, Details)},
         {description, proplists:get_value(description, Details)},
         {licenses, proplists:get_value(licenses, Details)},
         {dependencies, Deps}
        ],
    dep_info(Name, Version, Source, Common).

dep_info(_Name, _Version, {pkg, Name, Version, Sha256}, Common) ->
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(Sha256)}
    | Common ];

dep_info(_Name, _Version, {pkg, Name, Version, _InnerChecksum, OuterChecksum, _RepoConfig}, Common) ->
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:hex(Name, Version)},
        {sha256, string:lowercase(OuterChecksum)}
    | Common ];

dep_info(Name, _Version, {git, Git, {tag, Tag}}, Common) ->
    [
        {name, Name},
        {version, Tag},
        {purl, rebar3_sbom_purl:git(Name, Git, Tag)}
    | Common ];

dep_info(Name, Version, {git, Git, {branch, Branch}}, Common) ->
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:git(Name, Git, Branch)}
    | Common ];

dep_info(Name, Version, {git, Git, {ref, Ref}}, Common) ->
    [
        {name, Name},
        {version, Version},
        {purl, rebar3_sbom_purl:git(Name, Git, Ref)}
    | Common ];

dep_info(Name, Version, {git_subdir, Git, Ref, _Dir}, Common) ->
    dep_info(Name, Version, {git, Git, Ref}, Common);

dep_info(_Name, _Version, _Source, _Common) ->
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
