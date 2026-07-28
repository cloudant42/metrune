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
