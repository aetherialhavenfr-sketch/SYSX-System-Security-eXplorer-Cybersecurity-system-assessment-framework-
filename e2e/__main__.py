"""Command line: ``python -m e2e <profile> <base-url> [--secret LABEL=VALUE ...] [--callback-url URL] [--no-rescan]``

Use it only against a lab or training application you run yourself (see e2e/README.md).
"""
import argparse
import json
import sys

from e2e.harness import HarnessError, Run, load_profile


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m e2e", description="Run SYSX end to end against a lab target.")
    ap.add_argument("profile", help="profile name (sysx-lab, dvwa, juice-shop) or a path to a JSON profile")
    ap.add_argument("base_url", help="base URL of the lab application, e.g. http://127.0.0.1:4280")
    ap.add_argument("--secret", action="append", default=[], metavar="LABEL=VALUE",
                    help="secret for a credential in the profile (session cookie, token); repeatable")
    ap.add_argument("--callback-url", default="", help="URL the target can reach this machine on (enables SSRF checks at thorough intensity)")
    ap.add_argument("--no-rescan", action="store_true", help="skip the second, stability scan")
    ap.add_argument("--timeout", type=float, default=900.0, help="seconds to allow each scan")
    ap.add_argument("--json", action="store_true", help="print the result as JSON at the end")
    args = ap.parse_args(argv)
    secrets = {}
    for item in args.secret:
        label, sep, value = item.partition("=")
        if not sep or not label:
            ap.error("--secret must look like LABEL=VALUE")
        secrets[label] = value
    try:
        profile = load_profile(args.profile)
        result = Run(profile, args.base_url, secrets=secrets, callback_url=args.callback_url, scan_timeout=args.timeout,
                     rescan=not args.no_rescan).execute()
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    print("RESULT:", "PASS" if result["passed"] else "FAIL", f"({result['seconds']}s)")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
