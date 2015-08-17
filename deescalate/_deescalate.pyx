# -*- coding: utf-8 -*-

from libc.stdlib cimport malloc, free
import os
import pwd
import grp

HARD_CODED_CAPS = [
    b'chown', b'dac_override', b'dac_read_search', b'fowner', b'fsetid', b'kill', b'setgid',
    b'setuid', b'setpcap', b'linux_immutable', b'net_bind_service', b'net_broadcast', b'net_admin',
    b'net_raw', b'ipc_lock', b'ipc_owner', b'sys_module', b'sys_rawio', b'sys_chroot', b'sys_ptrace',
    b'sys_pacct', b'sys_admin', b'sys_boot', b'sys_nice', b'sys_resource', b'sys_time', b'sys_tty_config',
    b'mknod', b'lease', b'audit_write', b'audit_control', b'setfcap', b'mac_override', b'mac_admin',
    b'syslog', b'wake_alarm', b'block_suspend'
]

SECBIT_NOROOT = 1 << 0
SECBIT_NOROOT_LOCKED = 1 << 1
SECBIT_NO_SETUID_FIXUP = 1 << 2
SECBIT_NO_SETUID_FIXUP_LOCKED = 1 << 3
SECBIT_KEEP_CAPS = 1 << 4
SECBIT_KEEP_CAPS_LOCKED = 1 << 5

nb_hard_coded = len(HARD_CODED_CAPS)

SUPPORTED_CAPS = {}
"""
Capabilities supported by the running system
"""

INVERSE_SUPPORTED_CAPS = {}
SUPPORTED_CAPS_NAMES = set()
UNSUPPORTED_CAPS = {}
"""
Unsupported capabilities
"""

SUPPORTED_CAPS_VALUES = set()
FLAGS = {
    'effective': CAP_EFFECTIVE,
    'permitted': CAP_PERMITTED,
    'inheritable': CAP_INHERITABLE
}

IF UNAME_SYSNAME == "Linux":
    cdef make_supported_caps():
        global SUPPORTED_CAPS, SUPPORTED_CAPS_NAMES, SUPPORTED_CAPS_VALUES, INVERSE_SUPPORTED_CAPS
        cdef char* temp
        for i in range(CAP_LAST_CAP + 1):
            if CAP_IS_SUPPORTED(<cap_value_t> i) == 1:
                temp = cap_to_name(<cap_value_t> i)
                if temp != NULL:
                    cap_name = (<bytes>temp).lower()
                    cap_free(<void*> temp)
                    if cap_name and not cap_name.isdigit():
                        cap_name = cap_name[4:]
                        SUPPORTED_CAPS[cap_name] = i
                        INVERSE_SUPPORTED_CAPS[i] = cap_name
                    else:
                        if i <= (nb_hard_coded - 1):
                            UNSUPPORTED_CAPS[i] = HARD_CODED_CAPS[i]
                        else:
                            UNSUPPORTED_CAPS[i] = cap_name

        SUPPORTED_CAPS_NAMES = set(SUPPORTED_CAPS.keys())
        SUPPORTED_CAPS_VALUES = set(SUPPORTED_CAPS.values())

    make_supported_caps()

    cdef class CapabilitySet(object):
        cdef cap_flag_t flag
        def __init__(self, capset):
            self.flag = _string_to_flag(capset)

        def __iter__(self):
            cdef cap_flag_value_t flag_value
            cdef int res
            cdef cap_t current = cap_get_proc()
            if <void*>current != NULL:
                try:
                    for i in SUPPORTED_CAPS_VALUES:
                        res = cap_get_flag(current, <cap_value_t>i, self.flag, &flag_value)
                        if res == -1:
                            raise RuntimeError("error happened calling cap_get_flag")
                        if flag_value == CAP_SET:
                            yield i
                finally:
                    cap_free(<void*> current)
            else:
                raise RuntimeError("impossible to get the current capabilities")

        def __contains__(self, item):
            cdef cap_value_t cap = <cap_value_t> item if isinstance(item, int) else <cap_value_t> SUPPORTED_CAPS[bytes(item)]
            cdef cap_t current = cap_get_proc()
            cdef int res
            cdef cap_flag_value_t flag_value
            if <void*>current != NULL:
                try:
                    res = cap_get_flag(current, cap, self.flag, &flag_value)
                    if res == -1:
                        raise RuntimeError("error happened calling cap_get_flag")
                    return flag_value == CAP_SET
                finally:
                    cap_free(<void*> current)
            else:
                raise RuntimeError("impossible to get the current capabilities")

        cdef _modify(self, caps_to_modify, cap_flag_value_t flag_value=CAP_CLEAR):
            if len(caps_to_modify) == 0:
                return 0
            cdef cap_value_t* norm_caps_to_modify = <cap_value_t*> malloc(len(caps_to_modify) * sizeof(cap_value_t))
            cdef cap_t current
            try:
                current = cap_get_proc()
                try:
                    for idx, i in enumerate(caps_to_modify):
                        norm_caps_to_modify[idx] = <cap_value_t> i
                    res = cap_set_flag(current, self.flag, len(caps_to_modify), norm_caps_to_modify, flag_value)
                    if res == -1:
                        raise RuntimeError("error executing cap_set_flag")
                    res = cap_set_proc(current)
                    if res == -1:
                        raise RuntimeError("error executing cap_set_proc")
                finally:
                    if <void*> current:
                        cap_free(<void*> current)
            finally:
                free(<void*> norm_caps_to_modify)

        cpdef add(self, caps_to_add):
            cdef int res
            caps_to_add = _normalize_list_of_caps(caps_to_add)
            caps_to_add = caps_to_add.difference(set(self))
            self._modify(caps_to_add, CAP_SET)
            return len(caps_to_add)

        cpdef remove(self, caps_to_drop):
            cdef int res
            caps_to_drop = _normalize_list_of_caps(caps_to_drop)
            caps_to_drop = caps_to_drop.intersection(set(self))
            self._modify(caps_to_drop, CAP_CLEAR)
            return len(caps_to_drop)

        cpdef remove_all_except(self, caps_to_keep):
            caps_to_keep = _normalize_list_of_caps(caps_to_keep)
            caps_to_drop = set(SUPPORTED_CAPS_VALUES).difference(caps_to_keep)
            return self.remove(caps_to_drop)

        cpdef set(self, caps):
            caps_to_keep = _normalize_list_of_caps(caps)
            caps_to_clear = set(SUPPORTED_CAPS_VALUES).difference(caps_to_keep)
            self._modify(caps_to_keep, CAP_SET)
            self._modify(caps_to_clear, CAP_CLEAR)

    cdef class BoundingSet(object):
        def __init__(self):
            pass

        def __iter__(self):
            for i in SUPPORTED_CAPS_VALUES:
                if cap_get_bound(<cap_value_t> i) == CAP_SET:
                    yield i

        def __contains__(self, item):
            cdef cap_value_t cap = <cap_value_t> item if isinstance(item, int) else <cap_value_t> SUPPORTED_CAPS[bytes(item)]
            return cap_get_bound(<cap_value_t> cap) == CAP_SET

        cpdef remove(self, caps_to_drop):
            caps_to_drop = _normalize_list_of_caps(caps_to_drop)
            cdef int res
            for i in caps_to_drop:
                res = cap_drop_bound(<cap_value_t> i)
                if res == -1:
                    raise RuntimeError("error executing cap_drop_bound(%s)" % i)

        cpdef remove_all_except(self, caps_to_keep):
            caps_to_keep = _normalize_list_of_caps(caps_to_keep)
            caps_to_drop = set(self).difference(caps_to_keep)
            self.remove(caps_to_drop)

    permitted = CapabilitySet(CAP_PERMITTED)
    inheritable = CapabilitySet(CAP_INHERITABLE)
    effective = CapabilitySet(CAP_EFFECTIVE)
    bounding_set = BoundingSet()

    # noinspection PyUnresolvedReferences
    cpdef lockdown_account(uid=None, gid=None, caps_to_keep=None):
        """
        lockdown_account(uid=None, gid=None, caps_to_keep=None)
        Deescalate the privileges of the running process

        :param uid: switch to this UID (optional)
        :param gid: switch to this GID (optional)
        :param caps_to_keep: a list of capabilities to keep
        :raises RuntimError: if some operation fails
        """
        caps_to_keep = _normalize_list_of_caps(caps_to_keep)

        if b"setpcap" not in effective:
            if b"setpcap" not in permitted:
                raise RuntimeError("the current process doesn't have setpcap cap")
            else:
                effective.add(b"setpcap")
        if uid is not None:
            if b'setuid' not in effective:
                if b'setuid' not in permitted:
                    raise RuntimeError("the current process doesn't have setuid cap")
                else:
                    effective.add(b"setuid")
        if gid is not None:
            if b'setgid' not in effective:
                if b'setgid' not in permitted:
                    raise RuntimeError("the current process doesn't have setgid cap")
                else:
                    effective.add(b"setgid")

        set_noroot()
        set_keep_caps()
        set_no_setuid_fixup()
        if uid is not None:
            os.setgid(_normalize_gid(uid, gid))
            os.setuid(_normalize_uid(uid))

        capset = set(permitted).intersection(caps_to_keep)
        effective.add(b'setpcap')

        bounding_set.remove_all_except(capset)
        inheritable.set(capset)
        effective.set(capset)
        permitted.set(capset)

        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    cpdef get_securebits():
        """
        get_securebits()
        Return the currently defined secure bits

        :return: (the securebits as an int, a dict of securebits)
        """
        global SECBIT_NOROOT_LOCKED, SECBIT_NOROOT
        global SECBIT_KEEP_CAPS_LOCKED, SECBIT_KEEP_CAPS
        global SECBIT_NO_SETUID_FIXUP_LOCKED, SECBIT_NO_SETUID_FIXUP

        res = int(prctl(PR_GET_SECUREBITS, 0, 0, 0, 0))
        if res == -1:
            raise RuntimeError("get_securebits() failed")
        d = {
            'SECBIT_NOROOT': res & SECBIT_NOROOT,
            'SECBIT_NOROOT_LOCKED': res & SECBIT_NOROOT_LOCKED,
            'SECBIT_KEEP_CAPS': res & SECBIT_KEEP_CAPS,
            'SECBIT_KEEP_CAPS_LOCKED': res & SECBIT_KEEP_CAPS_LOCKED,
            'SECBIT_NO_SETUID_FIXUP': res & SECBIT_NO_SETUID_FIXUP,
            'SECBIT_NO_SETUID_FIXUP_LOCKED': res & SECBIT_NO_SETUID_FIXUP_LOCKED
        }
        return res, d

    cpdef set_noroot(locked=True):
        """
        set_noroot(locked=True)
        Set the `SECBIT_NOROOT` securebit.

        :param locked: if True, also set `SECBIT_NOROOT_LOCKED`
        :raises RuntimeError: if operation fails
        """
        global SECBIT_NOROOT_LOCKED, SECBIT_NOROOT
        current = get_securebits()[0]
        modified = (current | SECBIT_NOROOT_LOCKED | SECBIT_NOROOT) if locked else (current | SECBIT_NOROOT)
        res = int(prctl(PR_SET_SECUREBITS, <unsigned long> modified, 0, 0, 0))
        if res == -1:
            raise RuntimeError("set_noroot failed")

    cpdef set_keep_caps(locked=True):
        """
        set_keep_caps(locked=True)
        Set the `SECBIT_KEEP_CAPS` securebit.

        :param locked: if True, also set `SECBIT_KEEP_CAPS_LOCKED`
        :raises RuntimeError: if operation fails
        """
        global SECBIT_KEEP_CAPS_LOCKED, SECBIT_KEEP_CAPS
        current = get_securebits()[0]
        modified = (current | SECBIT_KEEP_CAPS_LOCKED | SECBIT_KEEP_CAPS) if locked else (current | SECBIT_KEEP_CAPS)
        res = int(prctl(PR_SET_SECUREBITS, <unsigned long> modified, 0, 0, 0))
        if res == -1:
            raise RuntimeError("set_keep_caps failed")

    cpdef set_no_setuid_fixup(locked=True):
        """
        set_no_setuid_fixup(locked=True)
        Set the `SECBIT_NO_SETUID_FIXUP` securebit.

        :param locked: if True, also set `SECBIT_NO_SETUID_FIXUP_LOCKED`
        :raises RuntimeError: if operation fails
        """
        global SECBIT_NO_SETUID_FIXUP_LOCKED, SECBIT_NO_SETUID_FIXUP
        current = get_securebits()[0]
        modified = (current | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NO_SETUID_FIXUP) if locked else (current | SECBIT_NO_SETUID_FIXUP)
        res = int(prctl(PR_SET_SECUREBITS, <unsigned long> modified, 0, 0, 0))
        if res == -1:
            raise RuntimeError("set_no_setuid_fixup failed")

ELSE:
    permitted = {}
    effective = {}
    inheritable = {}
    bounding_set = {}

    cpdef lockdown_account(uid=None, gid=None, caps_to_keep=None):
        """
        lockdown_account(uid=None, gid=None, caps_to_keep=None)
        Deescalate the privileges of the running process

        :param uid: switch to this UID (optional)
        :param gid: switch to this GID (optional)
        :param caps_to_keep: a list of capabilities to keep
        :raises RuntimeError: if some operation fails
        """

    cpdef get_securebits():
        """
        get_securebits()
        Return the currently defined secure bits

        :return: (the securebits as an int, a dict of securebits)
        """

    cpdef set_noroot(locked=True):
        """
        set_noroot(locked=True)
        Set the `SECBIT_NOROOT` securebit.

        :param locked: if True, also set `SECBIT_NOROOT_LOCKED`
        :raises RuntimeError: if operation fails
        """

    cpdef set_keep_caps(locked=True):
        """
        set_keep_caps(locked=True)
        Set the `SECBIT_KEEP_CAPS` securebit.

        :param locked: if True, also set `SECBIT_KEEP_CAPS_LOCKED`
        :raises RuntimeError: if operation fails
        """

    cpdef set_no_setuid_fixup(locked=True):
        """
        set_no_setuid_fixup(locked=True)
        Set the `SECBIT_NO_SETUID_FIXUP` securebit.

        :param locked: if True, also set `SECBIT_NO_SETUID_FIXUP_LOCKED`
        :raises RuntimeError: if operation fails
        """

cdef cap_flag_t _string_to_flag(capset):
    if isinstance(capset, int):
        if <cap_flag_t>capset == CAP_EFFECTIVE or <cap_flag_t>capset == CAP_PERMITTED or <cap_flag_t>capset == CAP_INHERITABLE:
            return <cap_flag_t> capset
        else:
            raise ValueError()
    if isinstance(capset, unicode):
        return <cap_flag_t> FLAGS[capset.encode('ascii').lower().strip()]
    if isinstance(capset, bytes):
        return <cap_flag_t> FLAGS[capset.lower().strip()]
    raise ValueError()

cdef _normalize_list_of_caps(list_of_caps):
    if list_of_caps is None:
        return set()
    if isinstance(list_of_caps, basestring):
        list_of_caps = [list_of_caps]
    list_of_caps = {cap.encode('ascii') if isinstance(cap, unicode) else cap for cap in list_of_caps}
    list_of_caps = {cap.lower().strip() if isinstance(cap, bytes) else cap for cap in list_of_caps}
    list_of_caps = {SUPPORTED_CAPS.get(cap) if isinstance(cap, bytes) else cap for cap in list_of_caps}
    list_of_caps = {None if isinstance(cap, int) and cap not in SUPPORTED_CAPS_VALUES else cap for cap in list_of_caps}
    list_of_caps = {cap for cap in list_of_caps if cap is not None}
    return set(list_of_caps)

cdef _normalize_uid(uid):
    return uid if isinstance(uid, int) else pwd.getpwnam(bytes(uid)).pw_uid

cdef _normalize_gid(uid, gid):
    if gid is not None:
        return gid if isinstance(gid, int) else grp.getgrnam(bytes(gid)).gr_gid
    elif isinstance(uid, int):
        return pwd.getpwuid(uid).pw_gid
    else:
        return pwd.getpwnam(bytes(uid)).pw_gid

import platform
if platform.system() != 'Linux' and 'SPHINX_BUILD' not in os.environ:
    raise ImportError("deescalate only works on Linux")

