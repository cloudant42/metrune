# Client distribution

How the `metrune` client reaches a developer machine, and what makes the bytes
that land there trustworthy.

## The split

The GitHub release is **canonical**. It is what CI builds, checksums, attests
with build provenance, and signs. Nothing else mints a release.

A Metrune server is an **optional mirror** in front of it. Workstations in
networks that cannot reach `github.com` still have to reach their Metrune server
— they upload usage to it — so the server is the one host guaranteed to be
reachable at install time. Mirroring removes the second network dependency
without moving the trust anchor.

|  | GitHub release | Metrune server |
|---|---|---|
| Builds the artifacts | yes | never |
| Signs the manifest | yes | never |
| Serves artifacts | yes | when mirrored |
| Decides the fleet's version floor | no | yes, via the manifest it publishes |
| Works air-gapped | no | yes |

Enterprises are expected to keep deploying the client through their normal
endpoint-management tooling (Intune, Jamf, apt/rpm repositories, winget,
Homebrew). Those pull from the canonical release; the mirror exists for
developers installing by hand and for networks with no egress.

## The manifest

`client-manifest.json` is the contract between the two. The release publishes
it as an asset; a server serves it at `GET /v1/client/manifest`.

```json
{
  "schemaVersion": 1,
  "version": "v0.3.0",
  "minimumVersion": "v0.2.0",
  "releasedAt": "2026-07-28T10:00:00Z",
  "upstreamBaseUrl": "https://github.com/metrune/metrune/releases/download/v0.3.0",
  "artifacts": [
    {
      "target": "linux-x86_64",
      "artifact": "metrune-linux-x86_64",
      "sha256": "…",
      "tier": "supported",
      "url": "https://metrune.example.com/v1/downloads/metrune-linux-x86_64",
      "source": "mirror"
    }
  ],
  "signature": "…"
}
```

The type lives in `crates/metrune-core/src/release.rs` and is shared by the
server, the client, and the release tooling, so the three cannot drift.

### What the signature covers

The signature is ed25519 over the manifest's **immutable** fields: schema
version, versions, release timestamp, upstream base URL, and each artifact's
target, file name, digest, and tier.

`url` and `source` are deliberately **outside** the signature. Rewriting them is
exactly what a mirror is for, and it stays safe because the client verifies the
bytes it downloads against the signed SHA-256 before running them. A mirror can
therefore change *where* a client fetches from, and can never change *what* a
valid client will accept.

The signing key belongs to the release pipeline and never reaches a deployment.
That is the point: a compromised self-hosted server must not be able to hand a
backdoored client to its own developers.

## Keys

| Where | Name | Value |
|---|---|---|
| Repository secret | `METRUNE_RELEASE_SIGNING_KEY` | base64 ed25519 private key, 32 bytes |
| Repository variable | `METRUNE_RELEASE_PUBKEY` | matching base64 public key |
| Repository variable | `MINIMUM_CLIENT_VERSION` | version floor published in the manifest |

`METRUNE_RELEASE_PUBKEY` is compiled into the client. A build without it still
reports available versions but refuses to self-install unless the operator
passes `--allow-unsigned`. Rotating the key means publishing a release built
with the new public key **before** signing with the new private key, or older
clients will reject the manifest.

Generate a pair with any ed25519 tool; the signing step prints the matching
public key so it can be pinned:

```
python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'
```

## Mirroring

The API serves a mirrored artifact only when it holds the file **and** the file
matches the digest in the manifest. A mismatch is refused and logged rather than
served, and the manifest keeps pointing that artifact upstream when the file is
absent, so a partially populated mirror degrades to "download from GitHub"
instead of failing.

| Variable | Default | Purpose |
|---|---|---|
| `METRUNE_CLIENT_DOWNLOAD_DIR` | `/usr/share/metrune/downloads` | Mirror cache; must contain `client-manifest.json` |
| `METRUNE_CLIENT_MANIFEST_PATH` | `<download dir>/client-manifest.json` | Manifest location, if it lives elsewhere |
| `METRUNE_CLIENT_RELEASE_BASE_URL` | `<server>/v1/downloads` | Where the web app links downloads |

The API image ships a manifest covering the Linux client built into it, so a
fresh deployment mirrors one platform with no setup. To mirror everything:

```
mkdir -p /srv/metrune/downloads && cd /srv/metrune/downloads
base=https://github.com/metrune/metrune/releases/download/v0.3.0
curl -fsSLO "$base/client-manifest.json"
for artifact in metrune-linux-x86_64 metrune-macos-arm64 \
                metrune-macos-x86_64 metrune-windows-x86_64.exe; do
  curl -fsSLO "$base/$artifact"
done
sha256sum -c SHA256SUMS   # after fetching SHA256SUMS from the same release
```

Mount that directory as `METRUNE_CLIENT_DOWNLOAD_DIR`. For an air-gapped
network, copy the directory in on removable media instead — the digests and the
signature travel with it, so it verifies exactly the same way.

## Installing

The server renders an installer from the manifest it holds, with URLs and
digests already substituted, so the script needs no JSON parser on the
workstation:

```
curl -fsSL https://metrune.example.com/v1/client/install.sh | sh
```

It selects the artifact for the running platform, verifies the SHA-256, and
installs to `/usr/local/bin` (override with `METRUNE_INSTALL_DIR`). Windows has
no shell installer; download the `.exe` from the release or the mirror and check
it against `SHA256SUMS`.

## Updating

```
metrune update --check     # report installed, published, and minimum versions
metrune update             # verify, download, and replace the running binary
```

`metrune update` reads the manifest from the server the installation is enrolled
with, so operators control the fleet's version through the manifest they
publish, and the client never has to reach GitHub. It verifies the manifest
signature against the pinned release key, verifies the downloaded artifact
against the signed digest, and replaces the running executable atomically.

The client reports when it is below `minimumVersion` so a developer sees the
floor before uploads start being refused. See
[RELEASING.md](RELEASING.md#client-compatibility) for the grace period that
applies before a floor is enforced.

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `GET /v1/client/manifest` | none | The release manifest, with mirrored artifacts rewritten to this server |
| `GET /v1/client/install.sh` | none | Installer rendered from the manifest |
| `GET /v1/downloads/{artifact}` | none | A mirrored artifact, served only when it matches the signed digest |

These are unauthenticated on purpose: a developer must install the client before
they can enroll it, so requiring a credential would be circular. Nothing served
is secret — the same bytes are public on the release page.
