# -*- coding: utf-8 -*-

__author__ = 'stephane.martin_github@vesperal.eu'

import argparse
import sys
import pwd
import grp
import shlex
import os

from . import lockdown_account, C

parser = argparse.ArgumentParser(
    usage="Deescalade current privileges to a given list of capabilities and run a command"
)
parser.add_argument("-u", "--user", help="run the specified command as user")
parser.add_argument("-g", "--group", help="run the specified command with this primary group")
caps_argument = parser.add_argument("-c", "--capabilities", help="comma-separated list of capabilities to keep")
parser.add_argument('-s', '--shell', action='store_true', help="run the command using a shell")
parser.add_argument('-d', '--dropenv', action='store_true', help="do not pass the environment variables to command")
parser.add_argument('--no-set-home', action='store_true', help="do not set the HOME env to the home dir of user")
parser.add_argument("command", help="run the specified command")
args = parser.parse_args()

supported_caps = C.SUPPORTED_CAPS_NAMES
capabilities = set([cap.strip().lower() for cap in args.capabilities.split(',')]) if args.capabilities else set()
user, group, command = args.user, args.group, args.command.strip()

if not capabilities.issubset(supported_caps):
    unsupported_caps = capabilities.difference(supported_caps)
    sys.stderr.write("Capabilities not supported: %s\n" % ','.join(unsupported_caps))
    sys.exit(1)

user_obj = None
if user is not None:
    try:
        user_obj = pwd.getpwnam(user)
    except KeyError:
        try:
            user_obj = pwd.getpwuid(int(user))
        except (KeyError, TypeError, ValueError):
            sys.stderr.write("User not known: %s\n" % user)
            sys.exit(1)

group_obj = None
if group is not None:
    try:
        group_obj = grp.getgrnam(group)
    except KeyError:
        try:
            group_obj = grp.getgrgid(int(group))
        except (KeyError, TypeError, ValueError):
            sys.stderr.write("Group not known: %s\n" % group)
            sys.exit(1)

lockdown_account(
    user_obj.pw_uid if user_obj is not None else None,
    group_obj.gr_gid if group_obj is not None else None,
    capabilities
)

new_env = {} if args.dropenv else os.environ.copy()
if (not args.no_set_home) and (user_obj is not None):
    new_env['HOME'] = user_obj.pw_dir
if user_obj is not None:
    new_env['USER'] = new_env['USERNAME'] = new_env['LOGNAME'] = user_obj.pw_name
try:
    del new_env['MAIL']             # can be set incorrectly by sudo...
except KeyError:
    pass

command_arguments = shlex.split(command)
if args.shell:
    command_arguments = ["/bin/sh", "-c"] + command_arguments
os.execvpe(command_arguments[0], command_arguments, new_env)

