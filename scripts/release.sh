#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "Usage: bash scripts/release.sh <version>"
  echo "Example: bash scripts/release.sh v1.0.0"
  exit 1
fi

cd "${PROJECT_ROOT}"

echo "[INFO] Step 1/3: test"
bash scripts/test.sh

echo "[INFO] Step 2/3: package"
bash scripts/package.sh "${VERSION}"

echo "[INFO] Step 3/3: release notes"
RELEASE_NOTE_PATH="dist/release-${VERSION}.md"
cat > "${RELEASE_NOTE_PATH}" <<EOF
# VPNProxy Release ${VERSION}

- Built at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- Artifact: vpnproxy-${VERSION}.tar.gz
- Checksum: vpnproxy-${VERSION}.tar.gz.sha256

## Validation checklist

- [x] Automated tests passed via scripts/test.sh
- [ ] Manual tests completed (see MANUAL_TEST_GUIDE.md)
- [ ] Deployment verification completed
EOF

echo "[INFO] Release prepared under dist/"
ls -1 dist
