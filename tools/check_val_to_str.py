#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Scan dissectors for calls to val_to_str() and friends,
# checking for appropriate format specifier strings in
# 'unknown' arg.
# TODO:
# - scan plugins and ASN.1 templates/configuration files
# - more detailed format specifier checking (check letter, that there is only 1)

import os
import re
import subprocess
import argparse
import signal


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)


# Test for whether the given file was automatically generated.
def isGeneratedFile(filename):
    # Open file
    f_read = open(os.path.join(filename), 'r')
    lines_tested = 0
    for line in f_read:
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if lines_tested > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Generated Automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1 or
            line.find('This file is auto generated') != -1):

            f_read.close()
            return True
        lines_tested = lines_tested + 1

    # OK, looks like a hand-written file!
    f_read.close()
    return False



def removeComments(code_string):
    code_string = re.sub(re.compile(r"/\*.*?\*/",re.DOTALL ) ,"" ,code_string) # C-style comment
    code_string = re.sub(re.compile(r"//.*?\n" ) ,"" ,code_string)             # C++-style comment
    return code_string


def is_dissector_file(filename):
    p = re.compile(r'.*packet-.*\.c')
    return p.match(filename)

def findDissectorFilesInFolder(folder):
    # Look at files in sorted order, to give some idea of how far through is.
    files = []

    for f in sorted(os.listdir(folder)):
        if should_exit:
            return
        if is_dissector_file(f):
            filename = os.path.join(folder, f)
            files.append(filename)
    return files



warnings_found = 0
errors_found = 0

# Check the given dissector file.
def checkFile(filename):
    global warnings_found
    global errors_found

    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    with open(filename, 'r') as f:
        contents = f.read()

        # Remove comments so as not to trip up RE.
        contents = removeComments(contents)

        matches =   re.finditer(r'(?<!try_)(?<!char_)(r?val_to_str(?:_ext|)(?:_const|))\(.*?,.*?,\s*(".*?\")\s*\)', contents)
        for m in matches:
            function = m.group(1)
            format_string = m.group(2)

            # Ignore what appears to be a macro.
            if format_string.find('#') != -1:
                continue

            if function.endswith('_const'):
                # These ones shouldn't have a specifier - its an error if they do.
                if format_string.find('%') != -1:
                    print('Error:', filename, "  ", m.group(0), '   - should not have specifiers in unknown string')
                    errors_found += 1
            else:
                # These ones need to have a specifier, and it should be suitable for an int.
                specifier_id = format_string.find('%')
                if specifier_id == -1:
                    print('Warning:', filename, "  ", m.group(0), '   - should have suitable format specifier in unknown string (or use _const()?)')
                    warnings_found += 1
                # TODO: check allowed specifiers (d, u, x, ?) and modifiers (0-9*) in re ?
                if format_string.find('%s') != -1:
                    print('Error:', filename, "  ", m.group(0), '    - inappropriate format specifier in unknown string')
                    errors_found += 1



#################################################################
# Main logic.

# command-line args.  Controls which dissector files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check calls in dissectors')
parser.add_argument('--file', action='append',
                    help='specify individual dissector file to test')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')

args = parser.parse_args()


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not f.startswith('epan'):
            f = os.path.join('epan', 'dissectors', f)
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Will examine dissector files only
    files = list(filter(lambda f : is_dissector_file(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files = list(filter(lambda f : is_dissector_file(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Only interested in dissector files.
    files_staged = list(filter(lambda f : is_dissector_file(f), files_staged))
    for f in files_staged:
        if not f in files:
            files.append(f)
else:
    # Find all dissector files from folder.
    files = findDissectorFilesInFolder(os.path.join('epan', 'dissectors'))


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Now check the files to see if they could have used shared ones instead.
for f in files:
    if should_exit:
        exit(1)
    if not isGeneratedFile(f):
        checkFile(f)


# Show summary.
print('')
print(warnings_found, 'warnings found')
if errors_found:
    print(errors_found, 'errors found')
    exit(1)
