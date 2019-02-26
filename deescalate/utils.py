# -*- coding: utf-8 -*-

__author__ = 'stephane.martin_github@vesperal.eu'

import pwd
import grp
from .constants import C

try:
    basestring
except NameError:
    basestring = str

try:
    unicode
except NameError:
    unicode = str

def normalize_list_of_caps(list_of_caps):
    if list_of_caps is None:
        return set()
    if isinstance(list_of_caps, basestring):
        list_of_caps = list_of_caps.lower().strip()
        if not list_of_caps:
            return set()
        list_of_caps = list_of_caps.split(',')
    list_of_caps = {cap.encode('ascii') if isinstance(cap, unicode) else cap for cap in list_of_caps}
    list_of_caps = {cap.lower().strip() if isinstance(cap, bytes) else cap for cap in list_of_caps}
    list_of_caps = {C.SUPPORTED_CAPS.get(cap) if isinstance(cap, bytes) else cap for cap in list_of_caps}
    list_of_caps = {None if isinstance(cap, int) and cap not in C.SUPPORTED_CAPS_VALUES else cap for cap in list_of_caps}
    list_of_caps = {cap for cap in list_of_caps if cap is not None}
    return set(list_of_caps)


def normalize_uid(uid):
    return uid if isinstance(uid, int) else pwd.getpwnam(bytes(uid)).pw_uid


def normalize_gid(uid, gid):
    if gid is not None:
        return gid if isinstance(gid, int) else grp.getgrnam(bytes(gid)).gr_gid
    elif isinstance(uid, int):
        return pwd.getpwuid(uid).pw_gid
    else:
        return pwd.getpwnam(bytes(uid)).pw_gid


def capset_string_to_flag(capset):
    if isinstance(capset, int):
        if capset in C.FLAGS.values():
            return capset
        else:
            raise ValueError()
    if isinstance(capset, unicode):
        return C.FLAGS[capset.encode('ascii').lower().strip()]
    if isinstance(capset, bytes):
        return C.FLAGS[capset.lower().strip()]
    raise ValueError()

