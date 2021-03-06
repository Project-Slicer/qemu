#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert plain qtest traces to C or Bash reproducers

Use this to help build bug-reports or create in-tree reproducers for bugs.
Note: This will not format C code for you. Pipe the output through
clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4, ColumnLimit: 90}"
or similar
"""

import sys
import os
import argparse
import textwrap
from datetime import date

__author__     = "Alexander Bulekov <alxndr@bu.edu>"
__copyright__  = "Copyright (C) 2021, Red Hat, Inc."
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Alexander Bulekov"
__email__      = "alxndr@bu.edu"


def c_header(owner):
    return """/*
 * Autogenerated Fuzzer Test Case
 *
 * Copyright (c) {date} {owner}
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "libqtest.h"

    """.format(date=date.today().year, owner=owner)

def c_comment(s):
    """ Return a multi-line C comment. Assume the text is already wrapped """
    return "/*\n * " + "\n * ".join(s.splitlines()) + "\n*/"

def print_c_function(s):
    print("/* ")
    for l in s.splitlines():
        print(" * {}".format(l))

def bash_reproducer(path, args, trace):
    result = '\\\n'.join(textwrap.wrap("cat << EOF | {} {}".format(path, args),
                                       72, break_on_hyphens=False,
                                       drop_whitespace=False))
    for l in trace.splitlines():
        result += "\n" + '\\\n'.join(textwrap.wrap(l,72,drop_whitespace=False))
    result += "\nEOF"
    return result

def c_reproducer(name, args, trace):
    result = []
    result.append("""static void {}(void)\n{{""".format(name))

    # libqtest will add its own qtest args, so get rid of them
    args = args.replace("-accel qtest","")
    args = args.replace(",accel=qtest","")
    args = args.replace("-machine accel=qtest","")
    args = args.replace("-qtest stdio","")
    result.append("""QTestState *s = qtest_init("{}");""".format(args))
    for l in trace.splitlines():
        param = l.split()
        cmd = param[0]
        if cmd == "write":
            buf = param[3][2:] #Get the 0x... buffer and trim the "0x"
            assert len(buf)%2 == 0
            bufbytes = [buf[i:i+2] for i in range(0, len(buf), 2)]
            bufstring = '\\x'+'\\x'.join(bufbytes)
            addr = param[1]
            size = param[2]
            result.append("""qtest_bufwrite(s, {}, "{}", {});""".format(
                          addr, bufstring, size))
        elif cmd.startswith("in") or cmd.startswith("read"):
            result.append("qtest_{}(s, {});".format(
                          cmd, param[1]))
        elif cmd.startswith("out") or cmd.startswith("write"):
            result.append("qtest_{}(s, {}, {});".format(
                          cmd, param[1], param[2]))
        elif cmd == "clock_step":
            if len(param) ==1:
                result.append("qtest_clock_step_next(s);")
            else:
                result.append("qtest_clock_step(s, {});".format(param[1]))
    result.append("qtest_quit(s);\n}")
    return "\n".join(result)

def c_main(name, arch):
    return """int main(int argc, char **argv)
{{
    const char *arch = qtest_get_arch();

    g_test_init(&argc, &argv, NULL);

   if (strcmp(arch, "{arch}") == 0) {{
        qtest_add_func("fuzz/{name}",{name});
   }}

   return g_test_run();
}}""".format(name=name, arch=arch)

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-bash", help="Only output a copy-pastable bash command",
                        action="store_true")
    group.add_argument("-c", help="Only output a c function",
                        action="store_true")
    parser.add_argument('-owner', help="If generating complete C source code, \
                        this specifies the Copyright owner",
                        nargs='?', default="<name of author>")
    parser.add_argument("-no_comment", help="Don't include a bash reproducer \
                        as a comment in the C reproducers",
                        action="store_true")
    parser.add_argument('-name', help="The name of the c function",
                        nargs='?', default="test_fuzz")
    parser.add_argument('input_trace', help="input QTest command sequence \
                        (stdin by default)",
                        nargs='?', type=argparse.FileType('r'),
                        default=sys.stdin)
    args = parser.parse_args()

    qemu_path = os.getenv("QEMU_PATH")
    qemu_args = os.getenv("QEMU_ARGS")
    if not qemu_args or not qemu_path:
        print("Please set QEMU_PATH and QEMU_ARGS environment variables")
        sys.exit(1)

    bash_args = qemu_args
    if " -qtest stdio" not in  qemu_args:
        bash_args += " -qtest stdio"

    arch = qemu_path.split("-")[-1]
    trace = args.input_trace.read().strip()

    if args.bash :
        print(bash_reproducer(qemu_path, bash_args, trace))
    else:
        output = ""
        if not args.c:
            output += c_header(args.owner) + "\n"
        if not args.no_comment:
            output += c_comment(bash_reproducer(qemu_path, bash_args, trace))
        output += c_reproducer(args.name, qemu_args, trace)
        if not args.c:
            output += c_main(args.name, arch)
        print(output)


if __name__ == '__main__':
    main()
