#!/usr/bin/python
#
# elfpatch - finds symbols in ELF files, applies patches at their locations
#
# Project page:  http://danielpocock.com/elfpatch
#
# Copyright (C) 2015 Daniel Pocock http://danielpocock.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
############################################################################
#
# Dependencies:
#
# - tested with python 2.7 on Debian 7.0
# - uses pyelftools from https://github.com/eliben/pyelftools
#
# Usage:
#
# - see help output
#
# - the symbol file contains symbol names and patches
#   each line contains a symbol name, a space and then the patch in hex, e.g.
#
#   __getFoo__ b800000000c3 
#
#   will patch the function getFoo so that it puts the value 0 in
#   register EAX (the return value) and then immediately returns
#   (for x86 binary architecture)
#
# - if pyelftools is not on the python path, then elfpatch must be
#   run from the root of the pyselftools source tree, or you must
#   modify the sys.path statement below
#
# Possible improvements
#
# - only do backups after successfully detecting the symbols
# - verify the binary architecture is correct for the patch or
#   allow multiple versions of each patch, per-architecture
# - scan all files before starting backups and patches
#   (currently does all backups, then scans and patches each file one by one
# - validate offsets found by scan, make sure they are all within file size,
#   validate patch size
# - scan using regexes instead of exact symbol names
# - allow some patches to be optional (proceed if some symbols not found)
# - provide a patching report file explaining exactly what was done
#

import argparse
import binascii
import os
import shutil
import sys
import mmap

# expects to be run from the root of the pyelftools source tree
sys.path[0:0] = ['.']

from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import Section
from elftools.elf.sections import SymbolTableSection

def process_file(do_write, syms, filename):
    addrs = dict()
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        print('%s: elfclass is %s' % (filename, elffile.elfclass))

        text_name = b'.text'
        sect_text = elffile.get_section_by_name(text_name)

        if not sect_text:
            print('  The file has no %s section' % bytes2str(text_name))
            return

        print('  %s section, sh_offset=%s sh_addr=%s' % (
            bytes2str(text_name), sect_text['sh_offset'], sect_text['sh_addr']))

        sect_st = elffile.get_section_by_name(b'.symtab')

        if not sect_st:
            print('  No symbol table found. Perhaps this ELF has been stripped?')
            return

        if not isinstance(sect_st, SymbolTableSection):
            print('  Not a valid symbol table')
            return

        for _sym in sect_st.iter_symbols():
            if _sym.name in syms.keys():
                sym_offset_in_file = sect_text['sh_offset'] - sect_text['sh_addr'] + _sym['st_value']
                print('found %s at virtual address %s, offset in file = %s' % 
                    (_sym.name,
                     hex(_sym['st_value']),
                     hex(sym_offset_in_file)) )
                addrs[_sym.name] = sym_offset_in_file

        if len(syms) > len(addrs):
            for sym_name in syms.keys():
                if not sym_name in addrs.keys():
                    print('   Failed to find symbol %s' % (sym_name))
            print('  Not all symbols found, aborting')
            return 
        else:
            print('  All required symbols found');
        f.close()

    if not do_write:
        print('   Scan-only mode, not writing any changes')
        return

    with open(filename, 'r+b') as f:
        print('   Writing patches to file...')
        for _sym in addrs.keys():
            f.seek(addrs[_sym])
            f.write(syms[_sym])
        f.close()

def get_syms(filename):
    syms = dict()
    with open(filename, 'r') as f:
        for line in f:
            fields = line.split()
            syms[fields[0]] = bytearray(binascii.a2b_hex(fields[1]))
    return syms

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='analyse and patch ELF files/executables')
    parser.add_argument('files', metavar='file',
        nargs='+', help='executable file to check/patch')
    parser.add_argument('--symbol-file', dest='symbol_file', required=True,
        help='file with list of symbols to scan for/patch')
    parser.add_argument('--apply', dest='apply',
        action='store_const', const='apply',
        help='apply the patches (default: do not patch any file)')
    parser.add_argument('--backup', dest='backup',
        action='store_const', const='backup',
        help='backup each file to filename.orig (implies --apply)')
    args = parser.parse_args()

    syms = get_syms(args.symbol_file)

    if args.backup:
        print('   Trying to make backups')
        for filename in args.files:
            backup_filename = filename + '.orig'
            if os.path.exists(backup_filename):
                print('   %s already exists, aborting' % (backup_filename))
                exit(1)
            shutil.copy2(filename, backup_filename)

    do_write = args.backup or args.apply
    if do_write:
        print('   Scanning files for symbols, patches will be applied')
    else:
        print('   Scanning files for symbols, patches will not be applied')
    for filename in args.files:
        process_file(do_write, syms, filename)

