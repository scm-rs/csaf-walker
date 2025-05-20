# sbom

A tool to work with SBOM data from the command line.

This tool can also be used as a library: <https://crates.io/crates/csaf-walker>

## Usage

```
Commands:
  discover  Discover SBOMs, just lists the URLs
  download  Like `sync`, but doesn't validate
  sync      Sync only what changed
  scan      Scan SBOMs
  report    Analyze (and report) the state of the data
  send      Walk a source and send validated/retrieved documents to a sink
  scoop     Walk a local directory (or single file) and send the files to a target without any validation
  inspect   Inspect SBOMs
  help      Print this message or the help of the given subcommand(s)
```

### Parse

Parse a CSAF document, or fail trying.

### Discover

Discover a list of URLs, pointing to CSAF document on a remove server. This will perform the lookup of the metadata,
and emit a URL per line with the discovered documents.

Example:

```
cargo run -- discover https://redhat.com
```

### Download

Discover and download CSAF documents.

### Sync

Discover, download, and validate CSAF documents.

This works similar to the `download` command, but will also perform some integrity validation (like digest, signatures).
It will, however, not verify the content of documents.

### Report

Discover, validate, and verify CSAF documents.

This discovers and temporarily downloads CSAF documents, performing validation and verification of the content.

**NOTE:** This commands works best of already downloaded data (a combination of running `download` and then `report`).

### Send

Discover, download, validate, and send CSAF documents to a remote endpoint.

Instead of storing content locally, this forwards content to a remote endpoint.

### Metadata

Take a source and try to discover the provider metadata. Showing the resulting JSON.

## Common options

### Sources

The CSAF tooling can discover and retrieve CSAF documents from two services: HTTP and file systems. Additionally,
when downloading CSAF documents, the tool will write content into the file system, so that it can later be used
as a file system source.

The idea behind that is that it is possible to split up the process of downloading and processing documents.

If a source string can be parsed as an `https` URL, it must point to the provider metadata. If the source string is
a `file` URL, it needs to point to a local file system location created by `sync` or `download`. Otherwise, the source
must be a domain name that will be used for discovering the CSAF provider metadata according to the specification.

**NOTE:** The structure of the filesystem storage is currently not considered an API. It is only guaranteed that
whatever is store can be read back by tools of the same version. Also, is it currently not a format which can be
hosted directly as a new CSAF repository.

### Signature verification

When signatures get verified, it may be possible that signature algorithms are considered "too old". If that's the case,
and you still want to allow them, it is possible to provide the "policy date", which sets the defaults for what is
still allowed (also see: <https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/>).

Specifically, when encountering GPG v3 signatures, one can also use the `-3` switch.
