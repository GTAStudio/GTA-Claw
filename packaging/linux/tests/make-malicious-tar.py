#!/usr/bin/env python3

import io
import sys
import tarfile


def entry(name: str, entry_type: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = entry_type
    info.linkname = linkname
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    return info


kind, output = sys.argv[1:3]
with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
    if kind == "traversal":
        info = entry("../escape", tarfile.REGTYPE)
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    elif kind == "symlink":
        archive.addfile(entry("unsafe-link", tarfile.SYMTYPE, "/etc/passwd"))
    elif kind == "hardlink":
        regular = entry("regular", tarfile.REGTYPE)
        regular.size = 1
        archive.addfile(regular, io.BytesIO(b"x"))
        archive.addfile(entry("unsafe-hardlink", tarfile.LNKTYPE, "regular"))
    elif kind == "fifo":
        archive.addfile(entry("unsafe-fifo", tarfile.FIFOTYPE))
    elif kind == "device":
        device = entry("unsafe-device", tarfile.CHRTYPE)
        device.devmajor = 1
        device.devminor = 3
        archive.addfile(device)
    elif kind == "whiteout":
        whiteout = entry(".wh.unsafe", tarfile.REGTYPE)
        whiteout.size = 0
        archive.addfile(whiteout, io.BytesIO())
    else:
        raise SystemExit(f"unsupported malicious tar kind: {kind}")
