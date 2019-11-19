rebar3_sbom
=====

Generates a Software Bill-of-Materials (SBoM) in CycloneDX format

Build
-----

    $ rebar3 compile

Use
---

Add the plugin to your rebar config, either in a project or globally in
~/.config/rebar3/rebar.config:

    {plugins, [rebar3_sbom]}.

Then just call your plugin directly in an existing application:


    $ rebar3 rebar3_sbom
    ===> Fetching rebar3_sbom
    ===> Compiling rebar3_sbom
    <Plugin Output>
