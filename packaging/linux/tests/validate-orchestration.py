#!/usr/bin/env python3

import re
import sys
from pathlib import Path

MAPPING = re.compile(r"^([ ]*)([^:#][^:]*):(?:[ ]*(.*))?$")


def scalar_paths(path: Path):
    stack = []
    values = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "\t" in raw:
            raise ValueError(f"{path}:{number}: tabs are not accepted")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("- "):
            continue
        match = MAPPING.match(raw)
        if match is None:
            continue
        indent = len(match.group(1))
        key = match.group(2).strip().strip("\"'")
        value = (match.group(3) or "").strip()
        if " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        value = value.strip("\"'")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        current = tuple(item[1] for item in stack) + (key,)
        if current in values:
            raise ValueError(f"{path}:{number}: duplicate mapping path: {'/'.join(current)}")
        values[current] = value
        if not value:
            stack.append((indent, key))
    return values


def require(values, path, expected, source):
    actual = values.get(path)
    if actual != expected:
        raise ValueError(
            f"{source}: {'/'.join(path)} must be {expected!r}, received {actual!r}"
        )


def main():
    if len(sys.argv) != 3:
        print("usage: validate-orchestration.py COMPOSE KUBERNETES", file=sys.stderr)
        return 2
    compose = Path(sys.argv[1])
    kubernetes = Path(sys.argv[2])
    try:
        require(
            scalar_paths(compose),
            ("services", "gta-claw", "depends_on", "gta-claw-init", "condition"),
            "service_completed_successfully",
            compose,
        )
        require(
            scalar_paths(kubernetes),
            ("spec", "strategy", "type"),
            "Recreate",
            kubernetes,
        )
    except (OSError, UnicodeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
