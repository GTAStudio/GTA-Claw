"""Strict substitution for the harness's small named-placeholder vocabulary."""

from __future__ import annotations

import re
from typing import Mapping


PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def render_template(value: str, context: Mapping[str, str]) -> str:
    """Replace `{name}` tokens without interpreting unrelated braces."""
    missing = sorted(set(PLACEHOLDER.findall(value)) - context.keys())
    if missing:
        raise ValueError(f"unknown performance placeholder(s): {', '.join(missing)}")
    return PLACEHOLDER.sub(lambda match: context[match.group(1)], value)

