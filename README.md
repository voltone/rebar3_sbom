rebar3_sbom
===========

Generates a Software Bill-of-Materials (SBoM) in CycloneDX format

Use
---

Add rebar3_sbom to your rebar config, either in a project or globally in
~/.config/rebar3/rebar.config:

    {plugins, [rebar3_sbom]}.

Then run the 'sbom' task on a project:

    $ rebar3 sbom
    ===> Verifying dependencies...
    ===> CycloneDX SBoM written to bom.xml

The following command line options are supported:

    -F, --format  the file format of the SBoM output, [xml|json], [default: xml]
    -o, --output  the full path to the SBoM output file [default: ./bom.[xml|json]]
    -f, --force   overwite existing files without prompting for confirmation
                  [default: false]
    -V, --strict_version modify the version number of the bom only when the content changes
                  [default: true]

By default only dependencies in the 'default' profile are included. To
generate an SBoM covering development environments specify the relevant
profiles using 'as':

    $ rebar3 as default,test,docs sbom -o dev_bom.xml
