#!/usr/bin/env python3

import ast
import re
import sys
from pathlib import Path, PurePosixPath

FORBIDDEN = frozenset({"bun", "node", "nodejs", "npm", "npx", "pnpm"})
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SHELL_SHEBANG = re.compile(r"^#!.*(?:ba|da|k|z)?sh(?:\s|$)")
FORBIDDEN_WORD = re.compile(
    r"(^|[^A-Za-z0-9_.-])(bun|node|nodejs|npm|npx|pnpm)(?=[^A-Za-z0-9_.-]|$)"
)
SEPARATORS = frozenset({"\n", ";", ";;", "&", "&&", "|", "||", "(", ")", "{", "}", "`"})
REDIRECTIONS = frozenset({"<", ">", "<<", ">>", "<>", "<&", ">&"})
RESERVED = frozenset(
    {
        "!",
        "case",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "function",
        "if",
        "in",
        "select",
        "then",
        "until",
        "while",
    }
)
SHELLS = frozenset({"ash", "bash", "dash", "ksh", "sh", "zsh"})
PREFIX_OPTIONS_WITH_VALUES = {
    "env": frozenset({"-C", "--chdir", "-S", "--split-string", "-u", "--unset"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "sudo": frozenset({"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-t", "-T", "-u"}),
}
SHELL_DIRECTORIES = frozenset({"debian", "direct", "libexec", "rpm"})
PYTHON_COMMAND_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.system",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)


def command_name(value):
    return PurePosixPath(value).name


def input_paths(arguments):
    seen = set()
    for argument in arguments:
        candidate = Path(argument)
        if candidate.is_symlink():
            raise ValueError(f"command surface must not be a symlink: {candidate}")
        paths = candidate.rglob("*") if candidate.is_dir() else (candidate,)
        for path in sorted(paths):
            if path in seen:
                continue
            if path.is_symlink():
                raise ValueError(f"command surface must not be a symlink: {path}")
            if not path.is_file():
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
                line += character == "\n"
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
                index += 1
                continue
            if character == "$" and text[index : index + 2] == "$(":
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
                else:
                    append(escaped)
                index += 2
                continue
            append(character)
            line += character == "\n"
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
        if character in ";&|(){}<>`":
            value = flush()
            if value is not None:
                yield value
            pair = text[index : index + 2]
            punctuation = pair if pair in {"&&", "||", ";;", "<<", ">>", "<>", "<&", ">&"} else character
            if punctuation == "(" and command_depth > 0:
                command_depth += 1
            elif punctuation == ")" and command_depth > 0:
                command_depth -= 1
            yield punctuation, line
            index += len(punctuation)
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


def command_segments(text):
    segment = []
    for token in shell_tokens(text):
        if token[0] in SEPARATORS:
            if segment:
                yield segment
                segment = []
        else:
            segment.append(token)
    if segment:
        yield segment


def remove_redirections(segment):
    cleaned = []
    index = 0
    while index < len(segment):
        token = segment[index][0]
        if token.isdecimal() and index + 1 < len(segment) and segment[index + 1][0] in REDIRECTIONS:
            index += 3
        elif token in REDIRECTIONS:
            index += 2
        else:
            cleaned.append(segment[index])
            index += 1
    return cleaned


def skip_options(tokens, index, command):
    options_with_values = PREFIX_OPTIONS_WITH_VALUES.get(command, ())
    while index < len(tokens):
        option = tokens[index][0]
        if option == "--":
            return index + 1
        if not option.startswith("-") or option == "-":
            return index
        index += 1
        if option in options_with_values and index < len(tokens):
            index += 1
    return index


def inspect_command(segment, depth=0):
    if depth > 16:
        raise ValueError("shell command recursion exceeds policy bound")
    tokens = remove_redirections(segment)
    index = 0
    while index < len(tokens) and (ASSIGNMENT.match(tokens[index][0]) or tokens[index][0] in RESERVED):
        index += 1
    if index >= len(tokens):
        return []
    command_token, line = tokens[index]
    command = command_name(command_token.lstrip("-+!:@"))
    findings = []
    if command in FORBIDDEN:
        findings.append((line, command))
    if command in SHELLS:
        index += 1
        while index < len(tokens):
            option = tokens[index][0]
            if option == "-c":
                if index + 1 < len(tokens):
                    findings.extend(inspect_shell(tokens[index + 1][0], line, depth + 1))
                break
            if option.startswith("-") or option == "--":
                index += 1
                continue
            break
        return findings
    if command == "eval":
        script = " ".join(token for token, _ in tokens[index + 1 :])
        findings.extend(inspect_shell(script, line, depth + 1))
        return findings
    if command == "command" and index + 1 < len(tokens) and tokens[index + 1][0] in {"-v", "-V"}:
        return findings
    if command in {"command", "env", "exec", "nice", "nohup", "setsid", "sudo", "time"}:
        index = skip_options(tokens, index + 1, command)
        while index < len(tokens) and ASSIGNMENT.match(tokens[index][0]):
            index += 1
        if index < len(tokens):
            findings.extend(inspect_command(tokens[index:], depth + 1))
    return findings


def inspect_shell(text, base_line=1, depth=0):
    findings = []
    for segment in command_segments(text):
        for line, command in inspect_command(segment, depth):
            findings.append((base_line + line - 1, command))
    return findings


def dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def literal_strings(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, (ast.List, ast.Tuple)):
        for element in node.elts:
            yield from literal_strings(element)


def inspect_python(path, text):
    findings = []
    tree = ast.parse(text, filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or dotted_name(node.func) not in PYTHON_COMMAND_CALLS:
            continue
        for argument in node.args:
            for value in literal_strings(argument):
                findings.extend(inspect_shell(value, node.lineno))
    return findings


def inspect_systemd(text):
    findings = []
    logical = text.replace("\\\n", "")
    for number, line in enumerate(logical.splitlines(), start=1):
        if not re.match(r"^Exec(?:Start|StartPre|Stop|StopPost|Reload|Condition)=", line):
            continue
        findings.extend(inspect_shell(line.split("=", 1)[1], number))
    return findings


def inspect_markdown(text):
    findings = []
    block = []
    start = 1
    shell_block = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("```"):
            if block and shell_block:
                findings.extend(inspect_shell("\n".join(block), start))
            block = []
            language = line[3:].strip().lower()
            shell_block = language in {"bash", "console", "sh", "shell"}
            start = number + 1
        elif shell_block:
            block.append(line)
    return findings


def inspect_dockerfile(text):
    findings = []
    logical = text.replace("\\\n", " ")
    for number, line in enumerate(logical.splitlines(), start=1):
        match = re.match(r"^\s*(RUN|CMD|ENTRYPOINT)\s+(.*)$", line, re.IGNORECASE)
        if match:
            findings.extend(inspect_shell(match.group(2), number))
    return findings


def shell_surface(path, text):
    relative_parts = set(path.parts)
    return (
        path.suffix in {".sh", ".in"}
        or bool(relative_parts & SHELL_DIRECTORIES)
        or SHELL_SHEBANG.match(text.splitlines()[0] if text.splitlines() else "")
    )


def inspect_path(path):
    text = path.read_text(encoding="utf-8")
    if shell_surface(path, text):
        return inspect_shell(text)
    if path.suffix == ".py":
        return inspect_python(path, text)
    if path.suffix == ".service":
        return inspect_systemd(text)
    if path.suffix in {".yaml", ".yml"}:
        return [
            (number, match.group(2))
            for number, line in enumerate(text.splitlines(), start=1)
            for match in [FORBIDDEN_WORD.search(line)]
            if match
        ]
    if path.name.startswith("Dockerfile"):
        return inspect_dockerfile(text)
    if path.suffix == ".md":
        return inspect_markdown(text)
    return []


def main():
    if len(sys.argv) < 2:
        print("usage: reject-javascript-commands.py PATH...", file=sys.stderr)
        return 2
    failed = False
    try:
        for path in input_paths(sys.argv[1:]):
            for number, command in inspect_path(path):
                print(
                    f"{path}:{number}: forbidden JavaScript command: {command}",
                    file=sys.stderr,
                )
                failed = True
    except (OSError, SyntaxError, UnicodeError, ValueError) as error:
        print(f"JavaScript command policy could not inspect input: {error}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
