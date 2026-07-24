#!/usr/bin/env python3

import re
import sys
from pathlib import Path

TOKEN = re.compile(
    r"(^|[^A-Za-z0-9_.-])(bun|node|nodejs|npm|npx|pnpm)(?=[^A-Za-z0-9_.-]|$)"
)
ALLOWED_POLICY_DATA = {
    "-iname 'node' -o -iname 'nodejs' -o -iname 'npm' -o -iname 'npx' -o \\",
    "-iname 'pnpm' -o -iname 'bun' -o -iname '*.js' -o -iname '*.mjs' -o \\",
    "grep -Eiq '(^|/)(node(js)?|npm|npx|pnpm|bun)(/|$)|\\.(js|mjs|cjs|node)$'; then",
}


def main():
    failed = False
    for argument in sys.argv[1:]:
        path = Path(argument)
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if TOKEN.search(line) and line.strip() not in ALLOWED_POLICY_DATA:
                print(
                    f"{path}:{number}: forbidden JavaScript command token",
                    file=sys.stderr,
                )
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
