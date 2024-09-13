-define(APP, "rebar3_sbom").
-define(DEFAULT_OUTPUT, "./bom.[xml|json]").
-define(DEFAULT_VERSION, 1).
-define(PROVIDER, sbom).
-define(DEPS, [lock]).

-record(metadata, {
    timestamp :: string(),
    tools = [] :: [string()]
}).

-record(component, {
    type = "library",
    bom_ref :: string(),
    author :: string(),
    name :: string(),
    version :: string(),
    description :: string(),
    hashes :: [#{alg := string(), hash := string()}],
    licenses :: [#{name := string()} | #{id := string()}],
    purl :: string()
}).

-record(dependency, {
    ref :: string(),
    dependencies = [] :: [#dependency{}]
}).

-record(sbom, {
    format = "CycloneDX" :: string(),
    version = ?DEFAULT_VERSION :: integer(),
    serial :: string(),
    metadata :: #metadata{},
    components :: [#component{}],
    dependencies :: [#dependency{}]
}).
