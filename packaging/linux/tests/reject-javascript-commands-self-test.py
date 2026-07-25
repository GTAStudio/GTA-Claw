#!/usr/bin/env python3

import subprocess
import sys
import tempfile
from pathlib import Path


CASES = {
    "quoted-concatenation.sh": "#!/bin/sh\nn''ode daemon.js\n",
    "continued-token.sh": "#!/bin/sh\nno\\\nde daemon.js\n",
    "combined-shell-options.sh": "#!/bin/sh\nbash -lc 'node daemon.js'\n",
    "shell-option-operand.sh": "#!/bin/sh\nbash -o errexit -c 'node daemon.js'\n",
    "eval.sh": "#!/bin/sh\neval 'node daemon.js'\n",
    "env-split.sh": "#!/bin/sh\nenv -S 'node daemon.js'\n",
    "timeout.sh": "#!/bin/sh\ntimeout 5 node daemon.js\n",
    "setpriv.sh": "#!/bin/sh\nsetpriv --clear-groups -- node daemon.js\n",
    "redirected-brace.sh": "#!/bin/sh\n{ node daemon.js; } >/dev/null\n",
    "generated-post": "#!/bin/sh\nexec /usr/bin/node daemon.js\n",
    "exec-argv-zero.sh": "#!/bin/sh\nexec -a daemon node daemon.js\n",
    "Dockerfile.exec": 'FROM scratch\nENTRYPOINT ["node", "daemon.js"]\n',
    "daemon.service": "[Service]\nExecStartPost=/usr/bin/node daemon.js\n",
    "command.py": (
        "import os, subprocess\n"
        "subprocess.run(args=['node', 'daemon.js'], check=True)\n"
        "os.execl('/usr/bin/node', 'node', 'daemon.js')\n"
    ),
    "imported-command.py": (
        "from subprocess import run\n"
        "run(['node', 'daemon.js'], check=True)\n"
    ),
}


def main():
    scanner = Path(__file__).with_name("reject-javascript-commands.py")
    with tempfile.TemporaryDirectory(prefix="gta-claw-js-policy-") as temporary:
        root = Path(temporary)
        for name, source in CASES.items():
            path = root / name
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, scanner, path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode != 1 or "forbidden JavaScript command" not in result.stderr:
                print(
                    f"JavaScript rejection self-test did not reject {name}: "
                    f"status={result.returncode} stderr={result.stderr!r}",
                    file=sys.stderr,
                )
                return 1

        allowed = root / "allowed.sh"
        allowed.write_text(
            "#!/bin/sh\nexec /usr/bin/python3 -c 'print(1)'\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, scanner, allowed],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            print(
                f"JavaScript rejection self-test rejected the allowed fixture: "
                f"status={result.returncode} stderr={result.stderr!r}",
                file=sys.stderr,
            )
            return 1

    print(f"JavaScript command rejection self-tests passed ({len(CASES) + 1} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
