# Versioning policy

Metrune uses one compatibility rule for the server and the native client, but
they are released independently.

## First release

The first release is `0.1.0` for both products:

- server packages and images: `server-v0.1.0`;
- native client: `client-v0.1.0`.

The `client-v0.1.0` tag contains every client operating-system artifact. Linux,
Windows, and both macOS targets never receive separate client version tags.

## Independent releases

The server version is the workspace/API version in `Cargo.toml`. The client
version is the `metrune` package version in `crates/metrune-cli/Cargo.toml`.
They may move independently after the first release. For example, a server
fix can ship as `server-v0.1.1` without a new client, while a client feature
can ship as `client-v0.2.0` without rebuilding the server images.

Use the namespaced tags exactly:

```text
server-vX.Y.Z
client-vX.Y.Z
```

The tag version must equal the corresponding package version. A server tag
never publishes canonical or signed client release artifacts (a development
API image may still carry its unsigned source-only Linux helper), and a client
tag never publishes server images. Production servers mirror the client release
they intend to support.

## SemVer rules

- Major version: the compatibility line. A server and client must have the
  same major version to use the upload protocol. A major transition requires
  a coordinated compatibility release and migration notes.
- Minor version: backward-compatible features and behavior within that major
  line. This rule applies to the `0.x` development line as well: `0.1` and
  `0.2` remain in the same compatibility line until `1.0` is declared.
- Patch version: fixes, reliability work, and security updates that do not
  change the wire contract. A security fix may use a minor version when it
  also needs a compatible protocol or feature change.

The server enforces the major-line rule on authenticated ingest and returns
the typed `client_unsupported` HTTP 426 response for a mismatched client. The
client checks `/v1/server/info` and prints the same compatibility guidance
before an upload when the mismatch is discoverable.

Within one major line, `METRUNE_MINIMUM_CLIENT_VERSION` may narrow the accepted
client floor after telemetry and a staged rollout. It must never select a
different major line.

## Release order

When a feature needs both products, publish the server compatibility support
first, then publish the client tag. When retiring an old client, publish the
client update and observe installation telemetry before raising the server
floor. Never use a tag from one product as the version of the other product.
