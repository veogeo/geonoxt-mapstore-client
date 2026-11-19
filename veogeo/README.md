# GeoNoXT MapStore overlay

This directory holds the GeoNoXT OIDC implementation and the small integration
patch needed to build it against upstream GeoNode MapStore. Upstream application
source stays at its upstream baseline on branch `cn-vg`; the build applies the
patch and copies these source modules into the build tree before compiling.

## Contents

- `src/client/js/noxt/oidc/`: provider-neutral OIDC discovery, PKCE, token
  storage and refresh scheduling, account adapter, and focused unit tests.
- `src/python/geonode_mapstore_client/noxt/`: public OIDC configuration view.
- `patches/geonode-oidc-integration.patch`: minimal wiring at MapStore/GeoNode
  extension points (API URL, store startup, account lookup and Django routes).
- `apply-overlay.sh`: idempotently applies the wiring patch and copies the
  GeoNoXT-owned source modules into the upstream build tree.

GeoNode API requests continue to use the browser's GeoNode session cookies.
Same-origin GeoServer Cloud OGC requests use the current OIDC access token as a
Bearer credential. The request interceptor refreshes it only when it is near
expiry and tries silent authorization through the provider's browser session
when the token is missing or expired. It attaches the token only to same-origin
`/geoserver/` and `/gs/` paths, never to GeoNode API requests or third-party
hosts; a failed token refresh does not end the GeoNode session.

## Local build

From the repository root on `cn-vg`:

```sh
./veogeo/apply-overlay.sh
cd geonode_mapstore_client/client
npm ci
npm run lint:ci
npm test
npm run compile
```

The manual GitHub Actions workflow performs the same overlay, checks and
production compilation before building and publishing the Python wheel release.
Do not commit generated `static/mapstore/dist/` output as part of the overlay.

## Updating upstream

Rebase `cn-vg` on the desired upstream commit, review and update only the patch
under `patches/` where upstream extension points changed, and keep custom OIDC
implementation under `src/`. Run the manual workflow from `cn-vg` to validate
and publish the wheel used by GeoNode.
