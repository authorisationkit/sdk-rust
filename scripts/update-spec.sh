#!/usr/bin/env bash
#
# Refresh the vendored OpenAPI document and regenerate the client.
#
#   ./scripts/update-spec.sh                      # production
#   ./scripts/update-spec.sh http://localhost:8099/openapi.json
#   AUTHKIT_SPEC_URL=... ./scripts/update-spec.sh
#
# The download is validated before it replaces the working copy. A spec is the
# only source of the client's entire public API here, so a truncated download,
# an HTML error page, or a server that has not been deployed yet would each
# silently rewrite every method signature in the crate. Each check below exists
# because it would otherwise land as a confusing compile error — or worse, as a
# client that compiles and calls the wrong thing.

set -euo pipefail

DEFAULT_URL="https://api.authkit.tech/openapi.json"
URL="${1:-${AUTHKIT_SPEC_URL:-$DEFAULT_URL}}"

cd "$(dirname "$0")/.."
SPEC="openapi.json"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
incoming="$scratch/openapi.json"

echo "Fetching $URL"
# --fail so a 4xx/5xx is an error rather than an error page written to disk.
if ! curl --fail --silent --show-error --location --max-time 30 "$URL" -o "$incoming"; then
    echo "error: could not fetch the spec from $URL" >&2
    exit 1
fi

# Validate the download before it is allowed to replace anything.
python3 - "$incoming" <<'PY'
import json, sys

path = sys.argv[1]
try:
    with open(path) as f:
        spec = json.load(f)
except json.JSONDecodeError as e:
    sys.exit(f"error: response is not valid JSON ({e})")

METHODS = ("get", "post", "put", "delete", "patch")
paths = spec.get("paths")
if not paths:
    sys.exit("error: spec has no paths — is this an OpenAPI document?")

ops = [
    (op.get("operationId"), method.upper(), path)
    for path, item in paths.items()
    for method, op in item.items()
    if method in METHODS and isinstance(op, dict)
]

missing = [f"{m} {p}" for oid, m, p in ops if not oid]
if missing:
    sys.exit("error: operations without an operationId:\n  " + "\n  ".join(missing))

# The operationId is the method name of every generated SDK. rocket-okapi
# derives one from the Rust module path when a route does not set it
# explicitly, which yields names like
# `crate_route_consumers_provide_register_provide_registration`. Accepting one
# would rename half the crate's public API — and the usual cause is pointing
# this script at a server that has not been redeployed, which is worth saying
# out loud rather than discovering in a diff.
derived = [oid for oid, _, _ in ops if oid.startswith("crate_") or "_route_" in oid]
if derived:
    sys.exit(
        "error: %d operationId(s) look module-derived, e.g. %r\n"
        "       This server predates the explicit operation ids. Deploy it, or\n"
        "       point the script at one that is current." % (len(derived), derived[0])
    )

print(f"  {len(ops)} operations, all with explicit ids")
PY

if [ -f "$SPEC" ] && cmp -s "$incoming" "$SPEC"; then
    echo "Spec is unchanged; nothing to regenerate."
    exit 0
fi

# Report what moved before overwriting, so the rebuild that follows is not the
# first sign that an endpoint appeared or vanished.
if [ -f "$SPEC" ]; then
    python3 - "$SPEC" "$incoming" <<'PY'
import json, sys

METHODS = ("get", "post", "put", "delete", "patch")

def ids(path):
    with open(path) as f:
        spec = json.load(f)
    return {
        op["operationId"]
        for item in spec.get("paths", {}).values()
        for method, op in item.items()
        if method in METHODS and isinstance(op, dict) and "operationId" in op
    }

old, new = ids(sys.argv[1]), ids(sys.argv[2])
for name in sorted(new - old):
    print(f"  + {name}")
for name in sorted(old - new):
    print(f"  - {name}")
if old == new:
    print("  (same operations; schemas or docs changed)")
PY
fi

mv "$incoming" "$SPEC"
echo "Updated $SPEC"

# build.rs declares rerun-if-changed on the spec, so this regenerates the
# client. Tests are where a breaking change actually shows up.
echo "Regenerating and testing…"
cargo test --all-features
