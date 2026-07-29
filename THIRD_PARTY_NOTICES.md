# Third-party software

Metrune includes open-source Rust, JavaScript, container-image, and build
dependencies. Each dependency remains subject to its own license and copyright
notice; the Apache-2.0 license for Metrune does not replace those terms.

Authoritative dependency inventories are:

- `Cargo.lock` for Rust packages;
- `web/package-lock.json` for dashboard packages;
- immutable image references in `compose.production.yaml`;
- the SBOM attached to each released API and web OCI image.

Release maintainers must review these inventories for license compatibility
and attach generated notices/SBOMs to release artifacts. This file is not a
claim that every dependency is redistributed inside every artifact.

## How that review is automated

- `deny.toml` lists every license permitted in the Rust dependency graph.
  `make licenses` (and the `rust-licenses` CI job) fails on anything outside
  it, so an incompatible dependency is caught in the pull request that adds
  it. Adding a license to the allow list is a deliberate policy change.
- `make notices` regenerates `NOTICE` from the resolved Rust graph and the
  installed dashboard tree, inlining the full text of every license that
  requires it to travel with the distribution. CI regenerates it on each run
  and uploads it as an artifact.
- `NOTICE` opens with an **Action required before release** section when a
  dependency carries such a license but ships no license file of its own.
  Those texts must be obtained upstream and pasted in before publishing.

Regenerate `NOTICE` on Linux x86_64: npm resolves platform-specific binaries,
and that is the platform of the published container images.
