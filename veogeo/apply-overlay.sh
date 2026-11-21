#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
overlay_root="$repo_root/veogeo"
patch_file="$overlay_root/patches/geonode-oidc-integration.patch"
mapstore_core="$repo_root/geonode_mapstore_client/client/MapStore2"
mapstore_core_patch="$overlay_root/patches/mapstore-wfst-schema-location.patch"
if git -C "$repo_root" apply --unidiff-zero --reverse --check "$patch_file" >/dev/null 2>&1; then
    echo "GeoNoXT MapStore integration patch already applied."
else
    # --index verifies the recorded upstream blob IDs before applying this
    # zero-context patch, so upstream drift fails instead of patching elsewhere.
    git -C "$repo_root" apply --index --unidiff-zero --check "$patch_file"
    git -C "$repo_root" apply --unidiff-zero "$patch_file"
    python3 - "$repo_root" <<'PY'
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
for relative in (
    "geonode_mapstore_client/apps.py",
    "geonode_mapstore_client/client/js/api/geonode/v2/constants.js",
    "geonode_mapstore_client/client/js/api/geonode/v2/index.js",
    "geonode_mapstore_client/client/js/utils/AppUtils.js",
    "geonode_mapstore_client/handlers.py",
    "geonode_mapstore_client/tests.py",
    "geonode_mapstore_client/views.py",
):
    original = subprocess.check_output(
        ["git", "-C", str(root), "show", f"HEAD:{relative}"]
    )
    if b"\r\n" in original:
        path = root / relative
        current = path.read_bytes().replace(b"\r\n", b"\n")
        path.write_bytes(current.replace(b"\n", b"\r\n"))
PY
    echo "Applied GeoNoXT MapStore integration patch."
fi
mkdir -p "$repo_root/geonode_mapstore_client/noxt"
cp -R "$overlay_root/src/python/geonode_mapstore_client/noxt/." "$repo_root/geonode_mapstore_client/noxt/"
mkdir -p "$repo_root/geonode_mapstore_client/client/js/noxt/oidc"
cp -R "$overlay_root/src/client/js/noxt/oidc/." "$repo_root/geonode_mapstore_client/client/js/noxt/oidc/"
echo "Installed GeoNoXT OIDC source modules."
if git -C "$mapstore_core" apply --reverse --check "$mapstore_core_patch" >/dev/null 2>&1; then
    echo "MapStore WFS-T schema patch already applied."
else
    git -C "$mapstore_core" apply --check "$mapstore_core_patch"
    git -C "$mapstore_core" apply "$mapstore_core_patch"
    echo "Applied MapStore WFS-T schema patch."
fi
mapstore_static_assets_patch="$overlay_root/patches/mapstore-static-assets.patch"
if git -C "$mapstore_core" apply --reverse --check "$mapstore_static_assets_patch" >/dev/null 2>&1; then
    echo "MapStore static asset output patch already applied."
else
    git -C "$mapstore_core" apply --check "$mapstore_static_assets_patch"
    git -C "$mapstore_core" apply "$mapstore_static_assets_patch"
    echo "Applied MapStore static asset output patch."
fi
