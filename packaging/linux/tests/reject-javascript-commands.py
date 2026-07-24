#!/usr/bin/env python3

import re
import sys
from pathlib import Path, PurePosixPath

FORBIDDEN = frozenset({"bun", "node", "nodejs", "npm", "npx", "pnpm"})
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SHELL_SHEBANG = re.compile(r"^#!.*(?:ba|da|k|z)?sh(?:\s|$)")
COMMAND_SEPARATORS = frozenset({"\n", ";", ";;", "&", "&&", "|", "||", "(", ")", "`"})
COMMAND_PREFIXES = frozenset({"command", "env", "exec", "nice", "nohup", "setsid", "sudo", "time"})
RESERVED_WORDS = frozenset(
    {"case", "do", "elif", "else", "for", "function", "if", "select", "then", "until", "while", "!"}
)
PREFIX_OPTIONS_WITH_VALUES = {
    "nice": frozenset({"-n", "--adjustment"}),
    "sudo": frozenset({"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-t", "-T", "-u"}),
}


def is_shell_surface(path):
    if path.suffix in {".sh", ".in"}:
        return True
    try:
        first_line = path.open(encoding="utf-8").readline()
    except (OSError, UnicodeError):
        return False
    return SHELL_SHEBANG.match(first_line) is not None


def input_paths(arguments):
    seen = set()
    for argument in arguments:
        candidate = Path(argument)
        paths = candidate.rglob("*") if candidate.is_dir() else (candidate,)
        for path in sorted(paths):
            if path in seen or path.is_symlink() or not path.is_file() or not is_shell_surface(path):
                continue
            seen.add(path)
            yield path


def shell_tokens(text):
    token = []
    token_line = 1
    line = 1
    quote = None
    command_depth = 0
    resume_quotes = []
    index = 0

    def append(character):
        nonlocal token_line
        if not token:
            token_line = line
        token.append(character)

    def flush():
        if token:
            value = "".join(token)
            token.clear()
            return value, token_line
        return None

    while index < len(text):
        character = text[index]
        if quote == "'":
            if character == "'":
                quote = None
            else:
                append(character)
                if character == "\n":
                    line += 1
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
                index += 1
                continue
            if character == "$" and index + 1 < len(text) and text[index + 1] == "(":
                append("$")
                value = flush()
                if value is not None:
                    yield value
                yield "(", line
                resume_quotes.append(('"', command_depth))
                command_depth += 1
                quote = None
                index += 2
                continue
            if character == "\\" and index + 1 < len(text):
                escaped = text[index + 1]
                if escaped == "\n":
                    line += 1
                elif escaped in COMMAND_SEPARATORS:
                    append("\\")
                    append(escaped)
                else:
                    append(escaped)
                index += 2
                continue
            append(character)
            if character == "\n":
                line += 1
            index += 1
            continue

        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if character == "\\" and index + 1 < len(text):
            escaped = text[index + 1]
            if escaped == "\n":
                line += 1
            elif escaped in COMMAND_SEPARATORS:
                append("\\")
                append(escaped)
            else:
                append(escaped)
            index += 2
            continue
        if character in " \t\r":
            value = flush()
            if value is not None:
                yield value
            index += 1
            continue
        if character == "\n":
            value = flush()
            if value is not None:
                yield value
            yield "\n", line
            line += 1
            index += 1
            continue
        if character == "#" and not token:
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        if character in ";&|()`":
            value = flush()
            if value is not None:
                yield value
            if character == "(" and command_depth > 0:
                command_depth += 1
            elif character == ")" and command_depth > 0:
                command_depth -= 1
            if index + 1 < len(text) and text[index : index + 2] in {"&&", "||", ";;"}:
                yield text[index : index + 2], line
                index += 2
            else:
                yield character, line
                index += 1
            if resume_quotes and command_depth == resume_quotes[-1][1]:
                quote, _ = resume_quotes.pop()
            continue
        append(character)
        index += 1

    if quote is not None:
        raise ValueError(f"unterminated {quote} quote")
    value = flush()
    if value is not None:
        yield value


def forbidden_commands(path):
    expect_command = True
    prefix = None
    skip_prefix_value = False

    for token, line in shell_tokens(path.read_text(encoding="utf-8")):
        if token in COMMAND_SEPARATORS:
            expect_command = True
            prefix = None
            skip_prefix_value = False
            continue
        if not token or not expect_command:
            continue
        if skip_prefix_value:
            skip_prefix_value = False
            continue
        if ASSIGNMENT.match(token) or token in RESERVED_WORDS:
            continue
        if token.startswith("-"):
            if prefix is not None and token in PREFIX_OPTIONS_WITH_VALUES.get(prefix, ()):
                skip_prefix_value = True
            continue

        command = PurePosixPath(token).name
        if command in FORBIDDEN:
            yield line, command
        if command in COMMAND_PREFIXES:
            prefix = command
            continue
        expect_command = False
        prefix = None


def main():
    if len(sys.argv) < 2:
        print("usage: reject-javascript-commands.py PATH...", file=sys.stderr)
        return 2

    failed = False
    try:
        for path in input_paths(sys.argv[1:]):
            try:
                commands = forbidden_commands(path)
                findings = list(commands)
            except ValueError as error:
                raise ValueError(f"{path}: {error}") from error
            for number, command in findings:
                print(
                    f"{path}:{number}: forbidden JavaScript command: {command}",
                    file=sys.stderr,
                )
                failed = True
    except (OSError, UnicodeError, ValueError) as error:
        print(f"JavaScript command policy could not inspect input: {error}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
