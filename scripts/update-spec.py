#!/usr/bin/env python3
"""Refresh the vendored OpenAPI document and regenerate the client.

    ./scripts/update-spec.py                                    # production
    ./scripts/update-spec.py http://localhost:8099/openapi.json # a local server

The download is validated before it replaces the working copy. This file is the
sole source of the crate's entire public API, so a truncated download, an HTML
error page from a proxy, or a server that has not been redeployed would each
silently rewrite every method signature in the crate. Each check below exists
because it would otherwise land as a confusing compile error — or worse, as a
client that compiles and calls the wrong thing.

Nothing else is needed to regenerate: `build.rs` declares `rerun-if-changed` on
the spec, so building is what runs progenitor.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = "https://api.authkit.tech/openapi.json"
TIMEOUT_SECONDS = 30
METHODS = ("get", "post", "put", "delete", "patch")

# urllib identifies itself as `Python-urllib/3.x`, which the CDN in front of
# api.authkit.tech answers with a 403 — so the default invocation of this script
# fails while the same URL is fine from a browser or curl. Send something
# specific instead: it gets past the block, and it makes this script findable in
# an access log when someone wonders who is pulling the spec.
USER_AGENT = "authorisationkit-update-spec/1.0 (+https://github.com/authorisationkit/sdk-rust)"

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "openapi.json"


class SpecError(Exception):
    """A problem with the fetched document that must stop the update."""


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.read()
    except urllib.error.HTTPError as err:
        raise SpecError(f"{url} returned HTTP {err.code} {err.reason}") from err
    except urllib.error.URLError as err:
        raise SpecError(f"could not reach {url}: {err.reason}") from err
    except TimeoutError as err:
        raise SpecError(f"{url} timed out after {TIMEOUT_SECONDS}s") from err


def operations(spec: dict) -> list[tuple[str | None, str, str]]:
    """Every operation as `(operationId, METHOD, path)`."""
    return [
        (operation.get("operationId"), method.upper(), path)
        for path, item in spec.get("paths", {}).items()
        for method, operation in item.items()
        if method in METHODS and isinstance(operation, dict)
    ]


def validate(raw: bytes) -> list[tuple[str | None, str, str]]:
    """Check the document is usable, returning its operations.

    Raises `SpecError` with something actionable rather than letting a bad
    document reach `openapi.json`.
    """
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError as err:
        raise SpecError(f"response is not valid JSON ({err})") from err

    if not isinstance(spec, dict) or not spec.get("paths"):
        raise SpecError("document has no paths — is this an OpenAPI spec?")

    ops = operations(spec)

    missing = [f"{method} {path}" for op_id, method, path in ops if not op_id]
    if missing:
        raise SpecError(
            "operations without an operationId:\n  " + "\n  ".join(missing)
        )

    # The operationId is the method name of every generated SDK. rocket-okapi
    # derives one from the Rust module path when a route does not set it
    # explicitly, giving names like
    # `crate_route_consumers_provide_register_provide_registration`. Accepting
    # one would rename half the crate's public API, and the usual cause is
    # pointing this at a server that has not been redeployed — worth saying out
    # loud rather than discovering in a diff.
    derived = [
        op_id for op_id, _, _ in ops if op_id.startswith("crate_") or "_route_" in op_id
    ]
    if derived:
        raise SpecError(
            f"{len(derived)} operationId(s) look module-derived, e.g. {derived[0]!r}\n"
            "This server predates the explicit operation ids. Deploy it, or point\n"
            "the script at one that is current."
        )

    return ops


def report_changes(previous: bytes, incoming: bytes) -> None:
    """Print which operations appeared or vanished.

    So that a rebuild is not the first sign an endpoint changed.
    """
    before = {op_id for op_id, _, _ in operations(json.loads(previous))}
    after = {op_id for op_id, _, _ in operations(json.loads(incoming))}

    for name in sorted(after - before):
        print(f"  + {name}")
    for name in sorted(before - after):
        print(f"  - {name}")
    if before == after:
        print("  (same operations; schemas or docs changed)")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=os.environ.get("AUTHKIT_SPEC_URL", DEFAULT_URL),
        help=f"where to fetch the document (default: {DEFAULT_URL}, "
        "or $AUTHKIT_SPEC_URL)",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="update the document but skip regenerating and testing",
    )
    args = parser.parse_args()

    print(f"Fetching {args.url}", flush=True)
    try:
        incoming = fetch(args.url)
        ops = validate(incoming)
    except SpecError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    print(f"  {len(ops)} operations, all with explicit ids")

    previous = SPEC_PATH.read_bytes() if SPEC_PATH.exists() else None
    if previous == incoming:
        print("Spec is unchanged; nothing to regenerate.")
        return 0

    if previous is not None:
        report_changes(previous, incoming)

    SPEC_PATH.write_bytes(incoming)
    print(f"Updated {SPEC_PATH.relative_to(REPO_ROOT)}")

    if args.no_test:
        print("Skipping regeneration (--no-test).")
        return 0

    # build.rs declares rerun-if-changed on the spec, so this regenerates the
    # client. Tests are where a breaking change actually shows up.
    print("Regenerating and testing…")
    return subprocess.run(
        ["cargo", "test", "--all-features"], cwd=REPO_ROOT
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
