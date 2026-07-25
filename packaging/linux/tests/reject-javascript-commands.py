#!/usr/bin/env python3

import ast
import json
import re
import shlex
import sys
from pathlib import Path, PurePosixPath

import yaml

FORBIDDEN = frozenset({"bun", "node", "nodejs", "npm", "npx", "pnpm"})
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SHELL_SHEBANG = re.compile(r"^#!.*(?:ba|da|k|z)?sh(?:\s|$)")
FORBIDDEN_WORD = re.compile(
    r"(^|[^A-Za-z0-9_.-])(bun|node|nodejs|npm|npx|pnpm)(?=[^A-Za-z0-9_.-]|$)"
)
SEPARATORS = frozenset({"\n", ";", ";;", "&", "&&", "|", "||", "(", ")", "{", "}", "`"})
REDIRECTIONS = frozenset({"<", ">", "<<", "<<<", ">>", "<>", "<&", ">&"})
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
    "exec": frozenset({"-a"}),
    "env": frozenset({"-C", "--chdir", "-S", "--split-string", "-u", "--unset"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "runuser": frozenset({"-g", "--group", "-G", "--supp-group", "-u", "--user"}),
    "setpriv": frozenset(
        {
            "--bounding-set",
            "--egid",
            "--euid",
            "--groups",
            "--inh-caps",
            "--keep-groups",
            "--regid",
            "--reuid",
        }
    ),
    "sudo": frozenset({"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-t", "-T", "-u"}),
    "stdbuf": frozenset({"-e", "--error", "-i", "--input", "-o", "--output"}),
    "timeout": frozenset({"-k", "--kill-after", "-s", "--signal"}),
    "xargs": frozenset(
        {
            "-a",
            "--arg-file",
            "-d",
            "--delimiter",
            "-E",
            "--eof",
            "-I",
            "--replace",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
        }
    ),
}
SHELL_DIRECTORIES = frozenset({"debian", "direct", "libexec", "rpm"})
PYTHON_COMMAND_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "os.execv",
        "os.execve",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execvp",
        "os.execvpe",
        "os.popen",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.system",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }
)
PYTHON_INTERPRETER = re.compile(r"^python(?:[0-9]+(?:\.[0-9]+)?)?$")
STATIC_VARIABLES = {
    "LINUX_DIR": "/trusted/linux",
    "LINUX_CLI_NAME": "gta-claw-cli",
    "LINUX_DAEMON_NAME": "gta-claw-daemon",
    "OUTPUT_ROOT": "/trusted/output",
    "REPO_ROOT": "/trusted/repository",
    "SAFEIO_HELPER": "/trusted/linux/safeio.py",
    "SAFEIO_BUILD_FD": "12",
    "SAFEIO_OUTPUT_FD": "11",
    "SAFEIO_TARGET_FD": "10",
    "SCRIPT_DIR": "/trusted/script",
}
TRUSTED_PATH_INITIALIZERS = {
    "SCRIPT_DIR": {
        '"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"',
        '"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"',
    },
    "LINUX_DIR": {
        '"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"',
    },
    "REPO_ROOT": {
        '"$(cd "$LINUX_DIR/../.." && pwd -P)"',
        '"$(cd "$SCRIPT_DIR/../.." && pwd -P)"',
    },
}
TRUSTED_DISCOVERED_PATH_INITIALIZERS = {
    'direct1="$(find "$direct_root/release1" -mindepth 1 -maxdepth 1 -type d)"': (
        "direct1=/trusted/direct-release1"
    ),
    'direct2="$(find "$direct_root/release2" -mindepth 1 -maxdepth 1 -type d)"': (
        "direct2=/trusted/direct-release2"
    ),
}


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def unique_yaml_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    unique_yaml_mapping,
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
            triple = text[index : index + 3]
            pair = text[index : index + 2]
            if triple == "<<<":
                punctuation = triple
            else:
                punctuation = (
                    pair
                    if pair in {"&&", "||", ";;", "<<", ">>", "<>", "<&", ">&"}
                    else character
                )
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
    test_terminator = None
    in_case = False
    expect_case_pattern = False
    for token in shell_tokens(text):
        value = token[0]
        if expect_case_pattern:
            if value == "esac":
                expect_case_pattern = False
                in_case = False
            elif value == ")":
                expect_case_pattern = False
            continue
        if (
            test_terminator is None
            and value in {"[", "[["}
            and all(existing[0] in RESERVED for existing in segment)
        ):
            test_terminator = "]" if value == "[" else "]]"
        if test_terminator is not None:
            segment.append(token)
            if value == test_terminator:
                test_terminator = None
        elif value in SEPARATORS:
            if segment:
                if segment[0][0] == "case":
                    in_case = True
                    expect_case_pattern = True
                elif segment[0][0] == "esac":
                    in_case = False
                yield segment
                segment = []
            if value == ";;" and in_case:
                expect_case_pattern = True
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


def inspect_env(tokens, index, depth, variables=None, allow_positional=False):
    while index < len(tokens):
        option, line = tokens[index]
        if option == "--":
            index += 1
            break
        if option in {"-S", "--split-string"}:
            if index + 1 >= len(tokens):
                raise ValueError(f"{option} requires a command string")
            try:
                split = shlex.split(tokens[index + 1][0], posix=True)
            except ValueError as error:
                raise ValueError(f"invalid env split string: {error}") from error
            return inspect_command(
                [(value, line) for value in split],
                depth + 1,
                variables,
                allow_positional,
            )
        if option.startswith("--split-string="):
            try:
                split = shlex.split(option.split("=", 1)[1], posix=True)
            except ValueError as error:
                raise ValueError(f"invalid env split string: {error}") from error
            return inspect_command(
                [(value, line) for value in split],
                depth + 1,
                variables,
                allow_positional,
            )
        if ASSIGNMENT.match(option):
            index += 1
            continue
        if not option.startswith("-") or option == "-":
            break
        next_index = skip_options(tokens, index, "env")
        if next_index == index:
            break
        index = next_index
    while index < len(tokens) and ASSIGNMENT.match(tokens[index][0]):
        index += 1
    return (
        inspect_command(
            tokens[index:],
            depth + 1,
            variables,
            allow_positional,
        )
        if index < len(tokens)
        else []
    )


def shell_command_string(tokens, index):
    while index < len(tokens):
        option = tokens[index][0]
        if option == "--":
            index += 1
            continue
        if option.startswith("-") and option != "-":
            short_options = option[1:] if not option.startswith("--") else ""
            if "c" in short_options:
                return index + 1
            if option in {"-o", "+o", "--init-file", "--rcfile"}:
                index += 2
                continue
            index += 1
            continue
        break
    return None


def expand_static(value, variables):
    unresolved = False

    def replace(match):
        nonlocal unresolved
        name = match.group(1) or match.group(2)
        if name not in variables:
            unresolved = True
            return match.group(0)
        return variables[name]

    expanded = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replace, value)
    return (
        None
        if unresolved
        or "$" in expanded
        or "`" in expanded
        else expanded
    )


def inspect_command(
    segment,
    depth=0,
    variables=None,
    allow_positional=False,
    allow_dynamic_lines=frozenset(),
):
    if depth > 16:
        raise ValueError("shell command recursion exceeds policy bound")
    variables = dict(STATIC_VARIABLES if variables is None else variables)
    tokens = remove_redirections(segment)
    if tokens and tokens[0][0] in {"case", "for", "select"}:
        return []
    index = 0
    while index < len(tokens) and ASSIGNMENT.match(tokens[index][0]):
        name, value = tokens[index][0].split("=", 1)
        expanded = expand_static(value, variables)
        if expanded is not None:
            variables[name] = expanded
        else:
            variables.pop(name, None)
        index += 1
    while index < len(tokens) and tokens[index][0] in RESERVED:
        index += 1
    while index < len(tokens) and ASSIGNMENT.match(tokens[index][0]):
        name, value = tokens[index][0].split("=", 1)
        expanded = expand_static(value, variables)
        if expanded is not None:
            variables[name] = expanded
        else:
            variables.pop(name, None)
        index += 1
    if index >= len(tokens):
        return []
    command_token, line = tokens[index]
    if command_name(command_token) in {"[", "[[", "test"}:
        return []
    if command_token.endswith("}") and command_token.startswith("/"):
        return []
    if any(character.isspace() for character in command_token):
        return []
    if command_token in {"$@", "$*"}:
        if allow_positional:
            return []
        raise ValueError("unresolved positional command is forbidden")
    expanded_command = expand_static(command_token, variables)
    if expanded_command is None:
        if line in allow_dynamic_lines:
            return []
        raise ValueError(
            f"unresolved dynamic command position at line {line}: {command_token}"
        )
    command = command_name(expanded_command.lstrip("-+!:@"))
    findings = []
    if command in FORBIDDEN:
        findings.append((line, command))
    if command in SHELLS:
        script_index = shell_command_string(tokens, index + 1)
        if script_index is not None:
            if script_index >= len(tokens):
                raise ValueError(f"{command} command option requires a script")
            findings.extend(
                inspect_shell(
                    tokens[script_index][0],
                    line,
                    depth + 1,
                    variables,
                    allow_positional,
                )
            )
        return findings
    if PYTHON_INTERPRETER.fullmatch(command):
        option_index = index + 1
        while option_index < len(tokens):
            option = tokens[option_index][0]
            if option == "-c":
                if option_index + 1 >= len(tokens):
                    raise ValueError("Python -c requires source")
                findings.extend(
                    inspect_python_text(tokens[option_index + 1][0], line)
                )
                return findings
            if option in {"-m", "-W", "-X"}:
                option_index += 2
                continue
            if option.startswith("-"):
                option_index += 1
                continue
            if command_name(option) == "safeio.py":
                try:
                    command_index = next(
                        candidate + 1
                        for candidate in range(option_index + 1, len(tokens))
                        if tokens[candidate][0] == "--"
                    )
                except StopIteration:
                    return findings
                if command_index < len(tokens):
                    findings.extend(
                        inspect_command(
                            tokens[command_index:],
                            depth + 1,
                            variables,
                            allow_positional,
                        )
                    )
            return findings
        return findings
    if command == "eval":
        script = " ".join(token for token, _ in tokens[index + 1 :])
        if re.fullmatch(r"exec \$[A-Za-z_][A-Za-z0-9_]*>&-", script):
            return findings
        findings.extend(inspect_shell(script, line, depth + 1, variables, allow_positional))
        return findings
    if command == "command" and index + 1 < len(tokens) and tokens[index + 1][0] in {"-v", "-V"}:
        return findings
    if command == "env":
        findings.extend(
            inspect_env(tokens, index + 1, depth, variables, allow_positional)
        )
        return findings
    if command == "gta-claw-safeio":
        try:
            command_index = next(
                candidate + 1
                for candidate in range(index + 1, len(tokens))
                if tokens[candidate][0] == "--"
            )
        except StopIteration:
            return findings
        if command_index < len(tokens):
            findings.extend(
                inspect_command(
                    tokens[command_index:],
                    depth + 1,
                    variables,
                    allow_positional,
                )
            )
        return findings
    if command == "timeout":
        index = skip_options(tokens, index + 1, command)
        if index < len(tokens):
            index += 1
        if index < len(tokens):
            findings.extend(inspect_command(tokens[index:], depth + 1, variables, allow_positional))
        return findings
    if command == "chroot":
        index = skip_options(tokens, index + 1, command)
        if index < len(tokens):
            index += 1
        if index < len(tokens):
            findings.extend(inspect_command(tokens[index:], depth + 1, variables, allow_positional))
        return findings
    if command in {
        "command",
        "exec",
        "nice",
        "nohup",
        "runuser",
        "setpriv",
        "setsid",
        "stdbuf",
        "sudo",
        "time",
        "xargs",
    }:
        index = skip_options(tokens, index + 1, command)
        while index < len(tokens) and ASSIGNMENT.match(tokens[index][0]):
            index += 1
        if index < len(tokens):
            findings.extend(inspect_command(tokens[index:], depth + 1, variables, allow_positional))
    return findings


def command_substitutions(text):
    def find_end(start):
        cursor = start
        depth = 1
        quote = None
        while cursor < len(text):
            character = text[cursor]
            if quote == "'":
                if character == "'":
                    quote = None
                cursor += 1
                continue
            if quote == '"':
                if character == "\\" and cursor + 1 < len(text):
                    cursor += 2
                    continue
                if character == '"':
                    quote = None
                    cursor += 1
                    continue
                if text[cursor : cursor + 2] == "$(":
                    cursor = find_end(cursor + 2)
                    continue
                cursor += 1
                continue
            if character == "\\" and cursor + 1 < len(text):
                cursor += 2
                continue
            if character == "'":
                quote = "'"
            elif character == '"':
                quote = '"'
            elif text[cursor : cursor + 2] in {"$(", "<(", ">("}:
                cursor = find_end(cursor + 2)
                continue
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return cursor + 1
            cursor += 1
        raise ValueError("unterminated command substitution")

    masked = []
    substitutions = []
    index = 0
    line = 1
    quote = None
    while index < len(text):
        character = text[index]
        if quote == "'":
            masked.append(character)
            if character == "'":
                quote = None
            line += character == "\n"
            index += 1
            continue
        if quote == '"' and character == '"':
            quote = None
            masked.append(character)
            index += 1
            continue
        if character == "\\" and index + 1 < len(text):
            masked.extend(text[index : index + 2])
            line += text[index + 1] == "\n"
            index += 2
            continue
        if character == "'" and quote is None:
            quote = "'"
            masked.append(character)
            index += 1
            continue
        if character == '"' and quote is None:
            quote = '"'
            masked.append(character)
            index += 1
            continue
        substitution = text[index : index + 2]
        if substitution == "$(" or (
            quote is None and substitution in {"<(", ">("}
        ):
            start_line = line
            inner_start = index + 2
            cursor = find_end(inner_start)
            content = text[inner_start : cursor - 1]
            substitutions.append((content, start_line))
            replacement = "$__GTA_CLAW_COMMAND_SUBSTITUTION__"
            replacement += "\\\n" * content.count("\n")
            masked.append(replacement)
            line += content.count("\n")
            index = cursor
            continue
        masked.append(character)
        line += character == "\n"
        index += 1
    return "".join(masked), substitutions


def inspect_shell(text, base_line=1, depth=0, variables=None, allow_positional=False):
    variables = dict(STATIC_VARIABLES if variables is None else variables)
    masked_text, substitutions = command_substitutions(text)
    heredoc_lines = set()
    heredoc_terminator = None
    for number, source_line in enumerate(masked_text.splitlines(), start=1):
        if heredoc_terminator is not None:
            heredoc_lines.add(number)
            if source_line == heredoc_terminator:
                heredoc_terminator = None
            continue
        stripped = source_line.strip()
        heredoc = re.search(r"<<-?['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", source_line)
        if heredoc:
            heredoc_terminator = heredoc.group(1)
    findings = [
        finding
        for content, line in substitutions
        for finding in inspect_shell(
            content,
            base_line + line - 1,
            depth + 1,
            variables,
            allow_positional,
        )
    ]
    for segment in command_segments(masked_text):
        cleaned = remove_redirections(segment)
        assignment_count = 0
        while (
            assignment_count < len(cleaned)
            and ASSIGNMENT.match(cleaned[assignment_count][0])
        ):
            assignment_count += 1
        if assignment_count == len(cleaned):
            for token, _ in cleaned:
                name, value = token.split("=", 1)
                expanded = expand_static(value, variables)
                if expanded is not None:
                    variables[name] = expanded
                else:
                    variables.pop(name, None)
        for line, command in inspect_command(
            segment,
            depth,
            variables,
            allow_positional,
            heredoc_lines,
        ):
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


def python_static_assignments(tree):
    assignments = {}
    for node in ast.walk(tree):
        values = []
        if isinstance(node, ast.Assign):
            values = [
                (target.id, node.value)
                for target in node.targets
                if isinstance(target, ast.Name)
            ]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            values = [(node.target.id, node.value)]
        for name, value in values:
            assignments.setdefault(name, []).append(value)
    return assignments


class StaticCommand(list):
    def __init__(self, values, complete=True):
        super().__init__(values)
        self.complete = complete


def python_static_command(
    node,
    assignments,
    resolving=frozenset(),
    shadowed=frozenset(),
):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
        and node.attr == "executable"
    ):
        return "/usr/bin/python3"
    if isinstance(node, (ast.List, ast.Tuple)):
        values = []
        complete = True
        for element in node.elts:
            if isinstance(element, ast.Starred):
                complete = False
                break
            try:
                value = python_static_command(
                    element,
                    assignments,
                    resolving,
                    shadowed,
                )
            except ValueError:
                if not values:
                    raise
                complete = False
                break
            if not isinstance(value, str):
                complete = False
                break
            values.append(value)
        if values:
            return StaticCommand(values, complete)
    if isinstance(node, ast.Name):
        if node.id in shadowed:
            raise ValueError(
                f"unresolved dynamic command position in Python at line {node.lineno}"
            )
        candidates = assignments.get(node.id, ())
        if len(candidates) == 1 and node.id not in resolving:
            return python_static_command(
                candidates[0],
                assignments,
                resolving | {node.id},
                shadowed,
            )
    raise ValueError(
        f"unresolved dynamic command position in Python at line {node.lineno}"
    )


def python_command_argument(name, node):
    if name.startswith("os.spawn"):
        return node.args[1] if len(node.args) > 1 else None
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in {"args", "cmd", "command"}:
            return keyword.value
    return None


def python_function_parameters(function):
    if function is None:
        return frozenset()
    arguments = function.args
    names = {
        argument.arg
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        )
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return frozenset(names)


def python_forwarded_command(program, arguments, skip, complete=True):
    if not isinstance(program, str):
        raise ValueError("Python executable path is not a static string")
    if not isinstance(arguments, StaticCommand):
        raise ValueError("Python command argv is not a static sequence")
    return StaticCommand(
        [program, *arguments[skip:]],
        complete and arguments.complete,
    )


def python_nodes_command(program, nodes, resolve):
    if not isinstance(program, str):
        raise ValueError("Python executable path is not a static string")
    values = [program]
    complete = True
    for node in nodes:
        try:
            value = resolve(node)
        except ValueError:
            complete = False
            break
        if not isinstance(value, str):
            complete = False
            break
        values.append(value)
    return StaticCommand(values, complete)


def python_effective_command(name, node, resolve):
    argument = python_command_argument(name, node)
    if argument is None:
        raise ValueError(
            f"unresolved dynamic command position in Python at line {node.lineno}"
        )
    if name in {
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
    }:
        program = resolve(node.args[0])
        return python_nodes_command(program, node.args[2:], resolve)
    if name in {"os.execv", "os.execve", "os.execvp", "os.execvpe"}:
        program = resolve(node.args[0])
        arguments = resolve(node.args[1])
        return python_forwarded_command(program, arguments, 1)
    if name in {"os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe"}:
        program = resolve(node.args[1])
        return python_nodes_command(program, node.args[3:], resolve)
    if name in {"os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe"}:
        program = resolve(node.args[1])
        arguments = resolve(node.args[2])
        return python_forwarded_command(program, arguments, 1)
    command = resolve(argument)
    if name.startswith("subprocess."):
        executable = next(
            (
                keyword.value
                for keyword in node.keywords
                if keyword.arg == "executable"
            ),
            None,
        )
        if executable is not None:
            program = resolve(executable)
            if isinstance(command, str):
                return StaticCommand([program], True)
            return python_forwarded_command(program, command, 1)
    if name == "asyncio.create_subprocess_exec":
        program = command
        return python_nodes_command(program, node.args[1:], resolve)
    return command


def inspect_python_command(command, line):
    if isinstance(command, str):
        return inspect_shell(command, line)
    findings = inspect_command([(value, line) for value in command])
    if findings:
        return findings
    if not command.complete:
        forwarded = command_name(command[0])
        if (
            forwarded in PREFIX_OPTIONS_WITH_VALUES
            or forwarded
            in {
                "chroot",
                "command",
                "eval",
                "gta-claw-safeio",
                "nohup",
                "setsid",
                "time",
            }
        ):
            raise ValueError(
                f"unresolved dynamic command position in Python at line {line}"
            )
    return findings


def inspect_python_text(text, base_line=1, path=None):
    findings = []
    tree = ast.parse(text)
    assignments = python_static_assignments(tree)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"asyncio", "os", "subprocess"}:
                    aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "asyncio",
            "os",
            "subprocess",
        }:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        first, separator, remainder = name.partition(".")
        if first in aliases:
            name = aliases[first] + (separator + remainder if separator else "")
        if name not in PYTHON_COMMAND_CALLS:
            continue
        parent = parents.get(node)
        while parent is not None and not isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            parent = parents.get(parent)
        shadowed = python_function_parameters(parent)
        resolve = lambda value: python_static_command(
            value,
            assignments,
            shadowed=shadowed,
        )
        try:
            command = python_effective_command(name, node, resolve)
        except ValueError:
            argument = python_command_argument(name, node)
            if (
                path is not None
                and path.name == "safeio.py"
                and parent is not None
                and parent.name == "run_child"
                and isinstance(argument, ast.Name)
                and argument.id == "command"
            ):
                continue
            raise
        command_line = base_line + node.lineno - 1
        findings.extend(inspect_python_command(command, command_line))
    return findings


def inspect_python(path, text):
    try:
        return inspect_python_text(text, path=path)
    except SyntaxError as error:
        error.filename = str(path)
        raise


def inspect_systemd(text):
    findings = []
    logical = text.replace("\\\n", "")
    for number, line in enumerate(logical.splitlines(), start=1):
        match = re.match(
            r"^\s*Exec(?:Condition|Reload|Start|StartPre|StartPost|Stop|StopPost)"
            r"\s*=\s*(.*)$",
            line,
        )
        if not match:
            continue
        command = match.group(1)

        def decode_escape(escape):
            value = escape.group(1)
            if value.startswith("x"):
                return chr(int(value[1:], 16))
            if value.startswith("u") or value.startswith("U"):
                return chr(int(value[1:], 16))
            if value[0] in "01234567":
                return chr(int(value, 8))
            simple = {
                "a": "\a",
                "b": "\b",
                "f": "\f",
                "n": "\n",
                "r": "\r",
                "s": " ",
                "t": "\t",
                "v": "\v",
                "\\": "\\",
                '"': '"',
                "'": "'",
            }
            if value not in simple:
                raise ValueError(f"unsupported systemd escape: \\{value}")
            return simple[value]

        command = re.sub(
            r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|"
            r"[0-7]{1,3}|.)",
            decode_escape,
            command,
        )
        findings.extend(inspect_shell(command, number))
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
            command = match.group(2)
            if command.lstrip().startswith("["):
                try:
                    arguments = json.loads(command)
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid Docker JSON command: {error}") from error
                if not isinstance(arguments, list) or not all(
                    isinstance(argument, str) for argument in arguments
                ):
                    raise ValueError("Docker JSON command must be an array of strings")
                if arguments:
                    findings.extend(
                        inspect_command(
                            [(argument, number) for argument in arguments],
                        )
                    )
            else:
                findings.extend(inspect_shell(command, number))
    return findings


def inspect_yaml_value(value, line=1):
    findings = []
    if isinstance(value, dict):
        command = value.get("command")
        arguments = value.get("args")
        if isinstance(command, list) and all(isinstance(item, str) for item in command):
            combined = list(command)
            if isinstance(arguments, list) and all(
                isinstance(item, str) for item in arguments
            ):
                combined.extend(arguments)
            findings.extend(inspect_command([(item, line) for item in combined]))
        for key, child in value.items():
            if key == "run" and isinstance(child, str):
                findings.extend(inspect_shell(child, line))
            elif key in {"command", "entrypoint"} and isinstance(child, str):
                findings.extend(inspect_shell(child, line))
            elif key == "entrypoint" and isinstance(child, list) and all(
                isinstance(item, str) for item in child
            ):
                findings.extend(inspect_command([(item, line) for item in child]))
            elif key == "image" and isinstance(child, str):
                image_name = child.split("@", 1)[0].rsplit("/", 1)[-1]
                image_command = image_name.split(":", 1)[0]
                if image_command in FORBIDDEN:
                    findings.append((line, image_command))
            findings.extend(inspect_yaml_value(child, line))
    elif isinstance(value, list):
        for child in value:
            findings.extend(inspect_yaml_value(child, line))
    return findings


def inspect_yaml(text):
    documents = list(yaml.load_all(text, Loader=UniqueKeyLoader))
    return [
        finding
        for document in documents
        for finding in inspect_yaml_value(document)
    ]


def shell_surface(path, text):
    relative_parts = set(path.parts)
    return (
        path.suffix in {".sh", ".in"}
        or bool(relative_parts & SHELL_DIRECTORIES)
        or SHELL_SHEBANG.match(text.splitlines()[0] if text.splitlines() else "")
    )


def normalize_trusted_path_initializers(text):
    normalized = []
    for line in text.splitlines(keepends=True):
        source = line.rstrip("\r\n")
        ending = line[len(source) :]
        if source in TRUSTED_DISCOVERED_PATH_INITIALIZERS:
            source = TRUSTED_DISCOVERED_PATH_INITIALIZERS[source]
        name, separator, value = source.partition("=")
        if separator and value in TRUSTED_PATH_INITIALIZERS.get(name, ()):
            source = f"{name}={STATIC_VARIABLES[name]}"
        normalized.append(source + ending)
    return "".join(normalized)


def inspect_path(path):
    text = path.read_text(encoding="utf-8")
    if path.name.endswith((".yaml.in", ".yml.in")):
        rendered = text.replace(
            "@OCI_IMAGE_REFERENCE@",
            "example.invalid/gta-claw@sha256:"
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef",
        )
        return inspect_yaml(rendered)
    if shell_surface(path, text):
        return inspect_shell(
            normalize_trusted_path_initializers(text),
            allow_positional=path.name.endswith("self-test.sh")
            or "tests" in path.parts,
        )
    if path.suffix == ".py":
        return inspect_python(path, text)
    if path.suffix == ".service":
        return inspect_systemd(text)
    if path.suffix in {".yaml", ".yml"}:
        return inspect_yaml(text)
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
            try:
                path_findings = inspect_path(path)
            except (SyntaxError, ValueError, yaml.YAMLError) as error:
                raise ValueError(f"{path}: {error}") from error
            for number, command in path_findings:
                print(
                    f"{path}:{number}: forbidden JavaScript command: {command}",
                    file=sys.stderr,
                )
                failed = True
    except (OSError, SyntaxError, UnicodeError, ValueError, yaml.YAMLError) as error:
        print(f"JavaScript command policy could not inspect input: {error}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
