"""`python3 -m warden <command> ...` dispatches to the module that owns the command. Each module's main() takes the arguments
after the command name."""

from __future__ import annotations

import importlib
import sys

COMMANDS = {
    "secretscan": "secretscan",
    "injection-eval": "injection_eval",
    "selftest": "selftest",
    "egress-proxy": "egress",
    "toolpolicy": "toolpolicy",
    "scope": "scope",
    "ownership": "ownership",
    "audit": "audit",
    "caps": "caps",
    "eligibility": "eligibility",
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python3 -m warden <command> [args]\ncommands: " + ", ".join(sorted(COMMANDS)))
        return 0 if argv else 2
    module = COMMANDS.get(argv[0])
    if module is None:
        print(f"warden: unknown command {argv[0]!r}", file=sys.stderr)
        return 2
    return int(importlib.import_module(f"warden.{module}").main(argv[1:]) or 0)


if __name__ == "__main__":
    sys.exit(main())
