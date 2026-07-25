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
    "xargs-options.sh": "#!/bin/sh\nprintf '%s\\n' daemon.js | xargs -n 1 node\n",
    "xargs-arg-file.sh": "#!/bin/sh\nxargs -a args.txt node daemon.js\n",
    "xargs-long-arg-file.sh": (
        "#!/bin/sh\nxargs --arg-file=args.txt node daemon.js\n"
    ),
    "while-command.sh": "#!/bin/sh\nwhile node daemon.js; do :; done\n",
    "while-comparison-argument.sh": (
        "#!/bin/sh\nwhile node -e daemon.js != expected; do :; done\n"
    ),
    "python-command.sh": (
        "#!/bin/sh\n"
        "python3 -c 'import subprocess; subprocess.run([\"node\", \"daemon.js\"])'\n"
    ),
    "redirected-brace.sh": "#!/bin/sh\n{ node daemon.js; } >/dev/null\n",
    "generated-post": "#!/bin/sh\nexec /usr/bin/node daemon.js\n",
    "exec-argv-zero.sh": "#!/bin/sh\nexec -a daemon node daemon.js\n",
    "Dockerfile.exec": 'FROM scratch\nENTRYPOINT ["node", "daemon.js"]\n',
    "daemon.service": "[Service]\nExecStartPost=/usr/bin/node daemon.js\n",
    "escaped-daemon.service": (
        "[Service]\nExecStart=/usr/bin/\\x6eode daemon.js\n"
    ),
    "indented-daemon.service": (
        "[Service]\n  ExecStart=/usr/bin/node daemon.js\n"
    ),
    "spaced-daemon.service": (
        "[Service]\nExecStartPost = /usr/bin/node daemon.js\n"
    ),
    "octal-daemon.service": (
        "[Service]\nExecStart=/usr/bin/\\156ode daemon.js\n"
    ),
    "escaped-command.yaml": 'command: ["\\u006eode", "daemon.js"]\n',
    "escaped-command.yaml.in": 'command: ["\\u006eode", "daemon.js"]\n',
    "entrypoint-list.yaml": "entrypoint: [node, daemon.js]\n",
    "registry-image.yaml": "image: registry.example:5000/node:20\n",
    "command.py": (
        "import os, subprocess\n"
        "subprocess.run(args=['node', 'daemon.js'], check=True)\n"
        "os.execl('/usr/bin/node', 'node', 'daemon.js')\n"
    ),
    "imported-command.py": (
        "from subprocess import run\n"
        "run(['node', 'daemon.js'], check=True)\n"
    ),
    "function-import.py": (
        "def launch():\n"
        "    from subprocess import run\n"
        "    run(['node', 'daemon.js'], check=True)\n"
    ),
    "variable-command.py": (
        "import subprocess\n"
        "command = ['node', 'daemon.js']\n"
        "subprocess.run(command, check=True)\n"
    ),
    "executable-command.py": (
        "import subprocess\n"
        "subprocess.run(['harmless', 'daemon.js'], executable='/usr/bin/node')\n"
    ),
    "exec-env-command.py": (
        "import os\n"
        "os.execl('/usr/bin/env', 'env', 'node', 'daemon.js')\n"
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

        dynamic = root / "dynamic.sh"
        dynamic.write_text("#!/bin/sh\n\"$unresolved_command\"\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, scanner, dynamic],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 2 or "unresolved dynamic command" not in result.stderr:
            print(
                "JavaScript rejection self-test accepted an unresolved command "
                f"position: status={result.returncode} stderr={result.stderr!r}",
                file=sys.stderr,
            )
            return 1

        for name, source in {
            "dynamic-substitution.sh": (
                "#!/bin/sh\nresult=$(\"$unresolved_command\")\nprintf '%s\\n' \"$result\"\n"
            ),
            "dynamic-xargs.sh": (
                "#!/bin/sh\nprintf '%s\\n' argument | xargs -n 1 \"$unresolved_command\"\n"
            ),
            "dynamic-continuation.sh": (
                "#!/bin/sh\n\\\n\"$unresolved_command\"\n"
            ),
            "dynamic-python.py": (
                "import subprocess\n"
                "def choose():\n"
                "    return input()\n"
                "command = choose()\n"
                "subprocess.run(command)\n"
            ),
            "dynamic-python-parameter.py": (
                "import subprocess\n"
                "command = ['true']\n"
                "def launch(command):\n"
                "    subprocess.run(command)\n"
                "launch(['node'])\n"
            ),
            "dynamic-python-env.py": (
                "import subprocess\n"
                "def launch(command):\n"
                "    subprocess.run(['env', command])\n"
                "launch('node')\n"
            ),
            "dynamic-shell-reassignment.sh": (
                "#!/bin/sh\ncmd=true\ncmd=$unresolved\n\"$cmd\"\n"
            ),
        }.items():
            dynamic = root / name
            dynamic.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, scanner, dynamic],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if (
                result.returncode != 2
                or "unresolved dynamic command" not in result.stderr
            ):
                print(
                    f"JavaScript rejection self-test accepted {name}: "
                    f"status={result.returncode} stderr={result.stderr!r}",
                    file=sys.stderr,
                )
                return 1

    print(f"JavaScript command rejection self-tests passed ({len(CASES) + 5} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
