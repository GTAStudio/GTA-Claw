#!/usr/bin/env python3

import json
import mmap
import re
import struct
import sys


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
DYNAMIC = struct.Struct("<qQ")
VERNEED = struct.Struct("<HHIII")
VERNAUX = struct.Struct("<IHHII")
GLIBC_VERSION = re.compile(r"GLIBC_([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")
GCC_VERSION = re.compile(r"GCC_[0-9]+(?:\.[0-9]+)*")
ARCH = {
    "x86_64": (62, "/lib64/ld-linux-x86-64.so.2"),
    "arm64": (183, "/lib/ld-linux-aarch64.so.1"),
}
ALLOWED_NEEDED = {"libc.so.6", "libgcc_s.so.1"}


def fail(message: str) -> None:
    raise SystemExit(f"strict-elf: {message}")


def bounded(data: mmap.mmap, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset + size > len(data):
        fail(f"{label} is outside the ELF file")
    return memoryview(data)[offset : offset + size]


def cstring(data: mmap.mmap, offset: int, limit: int, label: str) -> str:
    raw = bytes(bounded(data, offset, limit, label))
    terminator = raw.find(b"\0")
    if terminator < 0:
        fail(f"{label} is not NUL terminated")
    value = raw[:terminator]
    if not value or any(byte < 0x21 or byte > 0x7E for byte in value):
        fail(f"{label} is empty or noncanonical")
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def inspect(path: str, architecture: str, ceiling: str) -> dict:
    if architecture not in ARCH and architecture != "auto":
        fail(f"unsupported architecture: {architecture}")
    with open(path, "rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if len(data) < ELF_HEADER.size:
                fail("ELF header is truncated")
            header = ELF_HEADER.unpack_from(data, 0)
            ident = header[0]
            if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
                fail("expected ELF64 little-endian input")
            elf_type = header[1]
            machine = header[2]
            phoff, shoff = header[5], header[6]
            phentsize, phnum = header[9], header[10]
            shentsize, shnum = header[11], header[12]
            if architecture == "auto":
                matches = [name for name, values in ARCH.items() if values[0] == machine]
                if len(matches) != 1:
                    fail(f"unsupported ELF machine: {machine}")
                architecture = matches[0]
            expected_machine, expected_interpreter = ARCH[architecture]
            if elf_type != 3:
                fail(f"expected PIE/ET_DYN, found e_type={elf_type}")
            if machine != expected_machine:
                fail(f"machine mismatch: expected {expected_machine}, found {machine}")
            if phentsize != PROGRAM_HEADER.size or phnum > 1024:
                fail("program-header table is noncanonical")
            if shentsize != SECTION_HEADER.size or shnum > 65535:
                fail("section-header table is noncanonical")

            programs = []
            for index in range(phnum):
                offset = phoff + index * phentsize
                bounded(data, offset, phentsize, "program header")
                programs.append(PROGRAM_HEADER.unpack_from(data, offset))

            loads = [program for program in programs if program[0] == 1]

            def virtual_to_offset(address: int, size: int, label: str) -> int:
                for program in loads:
                    file_offset, virtual, file_size = program[2], program[3], program[5]
                    if virtual <= address and address + size <= virtual + file_size:
                        result = file_offset + address - virtual
                        bounded(data, result, size, label)
                        return result
                fail(f"{label} virtual address is not file-backed")

            interpreters = [program for program in programs if program[0] == 3]
            if len(interpreters) != 1:
                fail("expected exactly one PT_INTERP")
            interp = interpreters[0]
            interpreter_raw = bytes(
                bounded(data, interp[2], interp[5], "PT_INTERP")
            )
            if (
                not interpreter_raw.endswith(b"\0")
                or interpreter_raw.count(b"\0") != 1
            ):
                fail("PT_INTERP is not a single canonical NUL-terminated string")
            interpreter = interpreter_raw[:-1].decode("ascii", errors="strict")
            if interpreter != expected_interpreter:
                fail(
                    f"PT_INTERP mismatch: expected {expected_interpreter}, found {interpreter}"
                )

            dynamic_segments = [program for program in programs if program[0] == 2]
            if len(dynamic_segments) != 1:
                fail("expected exactly one PT_DYNAMIC")
            dynamic_program = dynamic_segments[0]
            if dynamic_program[5] % DYNAMIC.size != 0:
                fail("PT_DYNAMIC size is noncanonical")
            dynamic_entries = []
            for offset in range(
                dynamic_program[2],
                dynamic_program[2] + dynamic_program[5],
                DYNAMIC.size,
            ):
                tag, value = DYNAMIC.unpack_from(data, offset)
                dynamic_entries.append((tag, value))
                if tag == 0:
                    break
            if not dynamic_entries or dynamic_entries[-1][0] != 0:
                fail("PT_DYNAMIC lacks DT_NULL terminator")
            if any(tag in (15, 29) for tag, _ in dynamic_entries):
                fail("DT_RPATH/DT_RUNPATH is forbidden")
            strtabs = [value for tag, value in dynamic_entries if tag == 5]
            strsizes = [value for tag, value in dynamic_entries if tag == 10]
            if len(strtabs) != 1 or len(strsizes) != 1 or strsizes[0] > 16 * 1024 * 1024:
                fail("dynamic string table is noncanonical")
            strtab_offset = virtual_to_offset(strtabs[0], strsizes[0], "DT_STRTAB")
            needed = []
            for _, value in (entry for entry in dynamic_entries if entry[0] == 1):
                if value >= strsizes[0]:
                    fail("DT_NEEDED offset is outside DT_STRTAB")
                needed.append(
                    cstring(
                        data,
                        strtab_offset + value,
                        strsizes[0] - value,
                        "DT_NEEDED",
                    )
                )
            if not needed or len(needed) != len(set(needed)):
                fail("DT_NEEDED entries are empty or duplicated")
            if set(needed) - ALLOWED_NEEDED:
                fail(f"unexpected DT_NEEDED entries: {sorted(set(needed) - ALLOWED_NEEDED)}")
            if "libc.so.6" not in needed:
                fail("DT_NEEDED does not include libc.so.6")

            verneed_addresses = [
                value for tag, value in dynamic_entries if tag == 0x6FFFFFFE
            ]
            verneed_counts = [
                value for tag, value in dynamic_entries if tag == 0x6FFFFFFF
            ]
            if (
                len(verneed_addresses) != 1
                or len(verneed_counts) != 1
                or verneed_counts[0] == 0
                or verneed_counts[0] > 4096
            ):
                fail("DT_VERNEED/DT_VERNEEDNUM is noncanonical")
            dynamic_versions = set()
            needed_offset = virtual_to_offset(
                verneed_addresses[0], VERNEED.size, "DT_VERNEED"
            )
            visited = set()
            for need_index in range(verneed_counts[0]):
                if needed_offset in visited:
                    fail("dynamic Elf64_Verneed list loops")
                visited.add(needed_offset)
                bounded(data, needed_offset, VERNEED.size, "dynamic Elf64_Verneed")
                version, count, file_offset, aux_offset, next_offset = VERNEED.unpack_from(
                    data, needed_offset
                )
                if version != 1 or count == 0 or count > 4096:
                    fail("dynamic Elf64_Verneed is noncanonical")
                if file_offset >= strsizes[0]:
                    fail("dynamic version file name is outside DT_STRTAB")
                version_file = cstring(
                    data,
                    strtab_offset + file_offset,
                    strsizes[0] - file_offset,
                    "dynamic version file",
                )
                if version_file not in needed:
                    fail("dynamic version file is not a DT_NEEDED entry")
                aux_cursor = needed_offset + aux_offset
                aux_visited = set()
                for aux_index in range(count):
                    if aux_cursor in aux_visited:
                        fail("dynamic Elf64_Vernaux list loops")
                    aux_visited.add(aux_cursor)
                    bounded(data, aux_cursor, VERNAUX.size, "dynamic Elf64_Vernaux")
                    _, _, _, name_offset, aux_next = VERNAUX.unpack_from(data, aux_cursor)
                    if name_offset >= strsizes[0]:
                        fail("dynamic version name is outside DT_STRTAB")
                    name = cstring(
                        data,
                        strtab_offset + name_offset,
                        strsizes[0] - name_offset,
                        "dynamic version name",
                    )
                    if not (
                        GLIBC_VERSION.fullmatch(name)
                        or GCC_VERSION.fullmatch(name)
                    ):
                        fail(f"noncanonical dynamic version requirement: {name}")
                    dynamic_versions.add(name)
                    if aux_index == count - 1:
                        if aux_next != 0:
                            fail("dynamic Elf64_Vernaux count mismatch")
                    else:
                        if aux_next < VERNAUX.size:
                            fail("dynamic Elf64_Vernaux next offset is noncanonical")
                        aux_cursor += aux_next
                if need_index == verneed_counts[0] - 1:
                    if next_offset != 0:
                        fail("dynamic Elf64_Verneed count mismatch")
                else:
                    if next_offset < VERNEED.size or next_offset > 16 * 1024 * 1024:
                        fail("dynamic Elf64_Verneed next offset is noncanonical")
                    needed_offset += next_offset

            sections = []
            for index in range(shnum):
                offset = shoff + index * shentsize
                bounded(data, offset, shentsize, "section header")
                sections.append(SECTION_HEADER.unpack_from(data, offset))

            section_versions = set()
            for section in sections:
                section_type = section[1]
                if section_type != 0x6FFFFFFE:
                    continue
                section_offset, section_size, link = section[4], section[5], section[6]
                if link >= len(sections):
                    fail("version-needs string-table link is invalid")
                string_section = sections[link]
                strings_offset, strings_size = string_section[4], string_section[5]
                bounded(data, strings_offset, strings_size, "version string table")
                cursor = 0
                visited = set()
                while cursor < section_size:
                    if cursor + VERNEED.size > section_size:
                        fail("Elf64_Verneed exceeds version-needs section")
                    if cursor in visited or len(visited) > 4096:
                        fail("version-needs list loops or is too large")
                    visited.add(cursor)
                    needed_offset = section_offset + cursor
                    bounded(data, needed_offset, VERNEED.size, "Elf64_Verneed")
                    version, count, _, aux_offset, next_offset = VERNEED.unpack_from(
                        data, needed_offset
                    )
                    if version != 1 or count == 0 or count > 4096:
                        fail("Elf64_Verneed is noncanonical")
                    aux_cursor = aux_offset
                    aux_visited = set()
                    for _ in range(count):
                        if aux_cursor + VERNAUX.size > section_size - cursor:
                            fail("Elf64_Vernaux exceeds version-needs section")
                        if aux_cursor in aux_visited:
                            fail("Elf64_Vernaux list loops")
                        aux_visited.add(aux_cursor)
                        absolute = needed_offset + aux_cursor
                        bounded(data, absolute, VERNAUX.size, "Elf64_Vernaux")
                        _, _, _, name_offset, aux_next = VERNAUX.unpack_from(
                            data, absolute
                        )
                        if name_offset >= strings_size:
                            fail("version name is outside string table")
                        name = cstring(
                            data,
                            strings_offset + name_offset,
                            strings_size - name_offset,
                            "version name",
                        )
                        if not (
                            GLIBC_VERSION.fullmatch(name)
                            or GCC_VERSION.fullmatch(name)
                        ):
                            fail(f"noncanonical version requirement: {name}")
                        section_versions.add(name)
                        if aux_next == 0:
                            if len(aux_visited) != count:
                                fail("Elf64_Vernaux count mismatch")
                            break
                        if aux_next < VERNAUX.size:
                            fail("Elf64_Vernaux next offset is noncanonical")
                        aux_cursor += aux_next
                    if next_offset == 0:
                        break
                    if next_offset < VERNEED.size:
                        fail("Elf64_Verneed next offset is noncanonical")
                    cursor += next_offset

            if section_versions != dynamic_versions:
                fail("section and dynamic version requirements differ")
            glibc = sorted(
                (
                    match.group(0)[6:]
                    for value in dynamic_versions
                    if (match := GLIBC_VERSION.fullmatch(value))
                ),
                key=version_tuple,
            )
            if not glibc:
                fail("no canonical GLIBC version requirements found")
            maximum = glibc[-1]
            if version_tuple(maximum) > version_tuple(ceiling):
                fail(f"GLIBC requirement {maximum} exceeds ceiling {ceiling}")
            return {
                "architecture": architecture,
                "elfType": "ET_DYN",
                "interpreter": interpreter,
                "needed": sorted(needed),
                "versions": sorted(dynamic_versions),
                "maxGlibc": maximum,
            }


def main() -> None:
    if len(sys.argv) != 4:
        fail("usage: strict_elf.py ELF ARCH GLIBC_CEILING")
    print(json.dumps(inspect(sys.argv[1], sys.argv[2], sys.argv[3]), sort_keys=True))


if __name__ == "__main__":
    main()
