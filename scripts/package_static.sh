#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/release/linux-amd64-static}"
HELPER_DIR="${HELPER_DIR:-}"
GOOS="${GOOS:-linux}"
GOARCH="${GOARCH:-amd64}"
BIN_DIR="${OUT_DIR}/bin"
REQUIRED_TOOLS=(tdbdump gcore klist strings ps sqlite3 pdbedit ktutil)
MISSING_OR_DYNAMIC=()

fail() {
  echo "[-] $*" >&2
  exit 1
}

is_static_binary() {
  local file="$1"
  if ! command -v ldd >/dev/null 2>&1; then
    return 0
  fi
  local out
  out="$(ldd "$file" 2>&1 || true)"
  if grep -qiE 'not a dynamic executable|statically linked' <<<"$out"; then
    return 0
  fi
  return 1
}

resolve_helper() {
  local name="$1"
  local candidate=""
  if [[ -n "${HELPER_DIR}" && -x "${HELPER_DIR}/${name}" ]]; then
    candidate="${HELPER_DIR}/${name}"
  elif [[ ("$name" == "ps" || "$name" == "strings") && -n "${HELPER_DIR}" && -x "${HELPER_DIR}/busybox" ]]; then
    candidate="${HELPER_DIR}/busybox"
  elif [[ "$name" == "ps" || "$name" == "strings" ]] && command -v busybox >/dev/null 2>&1; then
    candidate="$(command -v busybox)"
  elif command -v "$name" >/dev/null 2>&1; then
    candidate="$(command -v "$name")"
  fi
  [[ -n "$candidate" ]] || fail "missing helper '${name}'. Set HELPER_DIR with static binaries."
  echo "$candidate"
}

echo "[*] Building static linikatz (${GOOS}/${GOARCH})"
rm -rf "$OUT_DIR"
mkdir -p "$BIN_DIR"

(
  cd "$ROOT_DIR"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags="-s -w" -o "${OUT_DIR}/linikatz" .
)

if ! is_static_binary "${OUT_DIR}/linikatz"; then
  fail "built linikatz is dynamic. Ensure pure-Go build settings are respected."
fi

echo "[*] Collecting static helper tools"
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! src="$(resolve_helper "$tool" 2>/dev/null)"; then
    MISSING_OR_DYNAMIC+=("${tool}:missing")
    continue
  fi
  cp -f "$src" "${BIN_DIR}/${tool}"
  chmod +x "${BIN_DIR}/${tool}"
  if ! is_static_binary "${BIN_DIR}/${tool}"; then
    MISSING_OR_DYNAMIC+=("${tool}:dynamic:${src}")
    continue
  fi
  echo "    + ${tool} <= ${src}"
done

if [[ "${#MISSING_OR_DYNAMIC[@]}" -gt 0 ]]; then
  echo "[-] Static helper validation failed:"
  for item in "${MISSING_OR_DYNAMIC[@]}"; do
    echo "    - ${item}"
  done
  fail "provide static helpers via HELPER_DIR and rerun"
fi

echo "[*] Writing checksums"
if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$OUT_DIR"
    sha256sum linikatz bin/* > SHA256SUMS
  )
elif command -v shasum >/dev/null 2>&1; then
  (
    cd "$OUT_DIR"
    shasum -a 256 linikatz bin/* > SHA256SUMS
  )
else
  echo "[!] sha256sum/shasum not found; skipping checksum file"
fi

TARBALL="${OUT_DIR}.tar.gz"
echo "[*] Creating tarball ${TARBALL}"
tar -C "$(dirname "$OUT_DIR")" -czf "$TARBALL" "$(basename "$OUT_DIR")"

cat <<EOF
[+] Static bundle ready:
    ${OUT_DIR}
[+] Tarball:
    ${TARBALL}
EOF
