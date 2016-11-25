#!/usr/bin/python

from __future__ import print_function
import sys
import logging
from struct import pack, unpack

import r2pipe

try:
    import colorlog
except ImportError:
    colorlog = None


def setup_logging(console=True, logfile=None, loglevel=logging.INFO,
                  name="r2gohelper"):
    log = logging.getLogger(name)
    log.handlers = []
    log.setLevel(loglevel)
    if console and colorlog is not None:
        handler = colorlog.StreamHandler()
        fmt = '%(log_color)s%(levelname)s%(reset)s : %(message)s'
        fmter = colorlog.ColoredFormatter(fmt)
        handler.setFormatter(fmter)
        log.addHandler(handler)
    elif console:
        fmt = '%(levelname)s : %(message)s'
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt))
        log.addHandler(handler)

    if logfile is not None:
        log.debug("logging to file '{}'".format(logfile))
        handler = logging.FileHandler(logfile)
        fmt = '%(asctime)s ; %(levelname)s ; %(name)s ; %(message)s'
        handler.setFormatter(logging.Formatter(fmt, "%Y-%m-%d %H:%M"))
        log.addHandler(handler)

    return log


log = setup_logging(loglevel=logging.DEBUG)
r2 = r2pipe.open()

BIN_INFO = r2.cmdj('ij')
PTR_SIZE = BIN_INFO['bin']['bits'] // 8
ARCH = BIN_INFO['bin']['arch']
BITS = BIN_INFO['bin']['bits']

GOFUNC_PREFIX = "go."

log.debug("ptr size is {}".format(PTR_SIZE))


def cmd(cmd, at_addr=None, json=False):
    if at_addr:
        c = "{} @ 0x{:x}".format(cmd, at_addr)
    else:
        c = cmd
    log.debug("cmd is '%s'", c)
    if json:
        r = r2.cmdj(c)
    else:
        r = r2.cmd(c)
    log.debug("res is %s", str(r))
    return r


def cmdj(*args, **kwargs):
    return cmd(*args, json=True, **kwargs)


def get_pointer_at(at_addr, size=None):
    if size:
        return int(cmd("pv{}".format(size), at_addr), 16)
    else:
        return int(cmd("pv", at_addr), 16)


def get_section_by_name(section_name):
    sections = cmdj("iSj")
    found = None
    for sec in sections:
        if sec['name'] == section_name:
            found = sec
    return found


def santize_gofunc_name(name):
    name = name.replace(" ", "_")
    name = name.replace(";", "_")
    name = name.replace(",", "_")
    return name


def create_runtime_morestack():
    log.info("Attempting to find 'runtime.morestack' function")
    text_seg = get_section_by_name('.text')
    text_vaddr = text_seg['vaddr']

    # This code string appears to work for ELF32 and ELF64 AFAIK
    s = "mov qword [0x1003], 0"
    res = cmdj("/aj " + s, text_seg)
    if not res:
        # let's search for the assembled variant
        if ARCH == "x86" and BITS == 64:
            h = "48c704250310.c3"
            res = cmdj("/xj " + h, text_seg)

    if not res:
        log.warning("Couldn't find morestack signature")
        return None

    if len(res) > 1:
        log.warning("more than one signature match... trying first")

    res = res[0]
    runtime_ms = cmdj("afij", res["offset"])[0]

    if not runtime_ms:
        log.warning("undefined function at morestack...")
        return None

    log.debug("runtime.morestack begins at 0x{:x}"
              .format(runtime_ms[offset]))

    if "morestack" not in runtime_ms["name"]:
        log.debug("renaming {} to 'runtime.morestack'"
                  .format(runtime_ms["name"]))
        cmd("afn {} {}".format("runtime.morestack", runtime_ms['offset']))

    return runtime_ms


def rename_functions():
    log.info("renaming functions based on .gopclntab section")

    gopclntab = get_section_by_name(".gopclntab")

    if gopclntab is None:
        log.error("Failed to find section '.gopclntab'")

    base_addr = gopclntab['paddr']
    size_addr = base_addr + 8
    size = get_pointer_at(size_addr, 4)

    log.debug("found .gopclntab section at 0x{:x} with {} entries"
              .format(base_addr, size / (PTR_SIZE * 2)))

    start_addr = size_addr + PTR_SIZE
    end_addr = base_addr + (size * PTR_SIZE * 2)

    for addr in range(start_addr, end_addr, (2 * PTR_SIZE)):
        log.debug("analyzing at 0x{:x}".format(addr))
        func_addr = get_pointer_at(addr)
        entry_offset = get_pointer_at(addr + PTR_SIZE)

        log.debug("func_addr 0x{:x}, entry offset 0x{:x}"
                  .format(func_addr, entry_offset))

        name_str_offset = get_pointer_at(base_addr + entry_offset + PTR_SIZE)
        name_addr = base_addr + name_str_offset

        name = cmd("psz", name_addr)
        log.debug("found name '{}' for address 0x{:x}".format(name, func_addr))

        funcinfo = cmdj("afij", func_addr)
        if name and len(name) > 2:
            name = GOFUNC_PREFIX + santize_gofunc_name(name)
            cmd("\"af{} {} {}\""
                .format("n" if funcinfo else "", name, func_addr))
        else:
            log.warning("not using function name '{}' for 0x{:x}"
                        .format(name, func_addr))
            if not funcinfo:
                cmd("af", func_addr)
                cmd("afna", func_addr)


if __name__ == "__main__":
    # log.info("We're gonna 'aa' first, this might take a while")
    # cmd("aa")

    rename_functions()
