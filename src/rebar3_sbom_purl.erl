-module(rebar3_sbom_purl).

% https://github.com/package-url/purl-spec

-export([hex/2, git/3, github/2, bitbucket/2]).

hex(Name, Version) ->
    purl(["hex", string:lowercase(Name)], Version).

git(_Name, "git@github.com:" ++ Github, Ref) ->
    Repo = string:replace(Github, ".git", "", trailing),
    github(Repo, Ref);

git(_Name, "https://github.com/" ++ Github, Ref) ->
    Repo = string:replace(Github, ".git", "", trailing),
    github(Repo, Ref);

git(_Name, "git://github.com/" ++ Github, Ref) ->
    Repo = string:replace(Github, ".git", "", trailing),
    github(Repo, Ref);

git(_Name, "git@bitbucket.org:" ++ Github, Ref) ->
    Repo = string:replace(Github, ".git", "", trailing),
    bitbucket(Repo, Ref);

git(_Name, "https://bitbucket.org/" ++ Github, Ref) ->
    Repo = string:replace(Github, ".git", "", trailing),
    bitbucket(Repo, Ref);

git(_Name, "git://bitbucket.org/" ++ Github, Ref) ->
    Repo = string:replace(Github, ".git", "", trailing),
    bitbucket(Repo, Ref);

%% Git dependence other than GitHub and BitBucket are not currently supported
git(_Name, _Git, _R) ->
    undefined.

github(Repo, Ref) ->
    [Organization, Name | _] = string:split(Repo, "/"),
    purl(["github", string:lowercase(Organization), string:lowercase(Name)], Ref).

bitbucket(Repo, Ref) ->
    [Organization, Name | _] = string:split(Repo, "/"),
    purl(["bitbucket", string:lowercase(Organization), string:lowercase(Name)], Ref).

purl(PathSegments, Version) ->
    Path = lists:join("/", [http_uri:encode(Segment) || Segment <- PathSegments]),
    io_lib:format("pkg:~s@~s", [Path, http_uri:encode(Version)]).
