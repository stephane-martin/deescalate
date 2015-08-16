# -*- coding: utf-8 -*-

from libc.stdlib cimport malloc, free
import os

HARD_CODED_CAPS = [
    b'chown', b'dac_override', b'dac_read_search', b'fowner', b'fsetid', b'kill', b'setgid',
    b'setuid', b'setpcap', b'linux_immutable', b'net_bind_service', b'net_broadcast', b'net_admin',
    b'net_raw', b'ipc_lock', b'ipc_owner', b'sys_module', b'sys_rawio', b'sys_chroot', b'sys_ptrace',
    b'sys_pacct', b'sys_admin', b'sys_boot', b'sys_nice', b'sys_resource', b'sys_time', b'sys_tty_config',
    b'mknod', b'lease', b'audit_write', b'audit_control', b'setfcap', b'mac_override', b'mac_admin',
    b'syslog', b'wake_alarm', b'block_suspend'
]

SECURE_NOROOT = 1 << 0
SECURE_NOROOT_LOCKED = 1 << 1
SECURE_NO_SETUID_FIXUP = 1 << 2
SECURE_NO_SETUID_FIXUP_LOCKED = 1 << 3
SECURE_KEEP_CAPS = 1 << 4
SECURE_KEEP_CAPS_LOCKED = 1 << 5

nb_hard_coded = len(HARD_CODED_CAPS)

SUPPORTED_CAPS = {}
INVERSE_SUPPORTED_CAPS = {}
SUPPORTED_CAPS_NAMES = set()
UNSUPPORTED_CAPS = {}
SUPPORTED_CAPS_VALUES = set()
FLAGS = {
    'effective': CAP_EFFECTIVE,
    'permitted': CAP_PERMITTED,
    'inheritable': CAP_INHERITABLE
}

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

cdef class Capabilities(object):
    def __init__(self):
        pass

    property bounding_set:
        def __get__(self):
            return self.get_bounding_set()

    property permitted:
        def __get__(self):
            return self.get_caps_in_set(CAP_PERMITTED)

    property effective:
        def __get__(self):
            return self.get_caps_in_set(CAP_EFFECTIVE)

    property inheritable:
        def __get__(self):
            return self.get_caps_in_set(CAP_INHERITABLE)

    cpdef get_caps_in_set(self, capset):
        cdef cap_flag_t flag = string_to_flag(capset)
        cdef cap_flag_value_t flag_value
        cdef int res
        results = set()
        cdef cap_t current = cap_get_proc()
        if <void*>current != NULL:
            try:
                for i in SUPPORTED_CAPS_VALUES:
                    res = cap_get_flag(current, <cap_value_t>i, flag, &flag_value)
                    if res == -1:
                        raise RuntimeError("error happened calling cap_get_flag")
                    if flag_value == CAP_SET:
                        results.add((i, INVERSE_SUPPORTED_CAPS[i]))
            finally:
                cap_free(<void*> current)
            return results
        else:
            raise RuntimeError("impossible to get the current capabilities")

    cpdef get_bounding_set(self):
        s = set()
        for i in SUPPORTED_CAPS_VALUES:
            if cap_get_bound(<cap_value_t> i) == CAP_SET:
                s.add((i, INVERSE_SUPPORTED_CAPS[i]))
        return s

    cpdef limit_caps_in_one_set(self, caps_to_keep, capset):
        caps_to_keep = set(normalize_list_of_caps(caps_to_keep))
        caps_to_drop = set(SUPPORTED_CAPS_VALUES).difference(caps_to_keep)
        self.drop_caps_from_one_set(caps_to_drop, capset)

    cpdef drop_caps_from_one_set(self, caps_to_drop, capset):
        cdef int res
        cdef cap_flag_t flag = string_to_flag(capset)
        caps_to_drop = set(normalize_list_of_caps(caps_to_drop))
        current_caps = set([cap[0] for cap in self.get_caps_in_set(capset)])
        caps_to_drop = caps_to_drop.intersection(current_caps)
        if len(caps_to_drop) == 0:
            return 0
        cdef cap_value_t* norm_caps_to_drop = <cap_value_t*> malloc(len(caps_to_drop) * sizeof(cap_value_t))
        cdef cap_t current
        try:
            current = cap_get_proc()
            try:
                for idx, i in enumerate(caps_to_drop):
                    norm_caps_to_drop[idx] = <cap_value_t> i
                res = cap_set_flag(current, flag, len(caps_to_drop), norm_caps_to_drop, CAP_CLEAR)
                if res == -1:
                    raise RuntimeError("error executing cap_set_flag")
                res = cap_set_proc(current)
                if res == -1:
                    raise RuntimeError("error executing cap_set_proc")
            finally:
                if <void*> current:
                    cap_free(<void*> current)
        finally:
            free(<void*> norm_caps_to_drop)
        return len(caps_to_drop)


    cpdef add_caps_to_one_set(self, caps_to_add, capset):
        cdef int res
        cdef cap_flag_t flag = string_to_flag(capset)
        caps_to_add = set(normalize_list_of_caps(caps_to_add))
        current_caps = set([cap[0] for cap in self.get_caps_in_set(capset)])
        caps_to_add = caps_to_add.intersection(set(SUPPORTED_CAPS_VALUES))
        caps_to_add = caps_to_add.difference(current_caps)
        if len(caps_to_add) == 0:
            return 0
        cdef cap_value_t* norm_caps_to_add = <cap_value_t*> malloc(len(caps_to_add) * sizeof(cap_value_t))
        cdef cap_t current
        try:
            current = cap_get_proc()
            try:
                for idx, i in enumerate(caps_to_add):
                    norm_caps_to_add[idx] = <cap_value_t> i
                res = cap_set_flag(current, flag, len(caps_to_add), norm_caps_to_add, CAP_SET)
                if res == -1:
                    raise RuntimeError("error executing cap_set_flag")
                res = cap_set_proc(current)
                if res == -1:
                    raise RuntimeError("error executing cap_set_proc")
            finally:
                if <void*> current:
                    cap_free(<void*> current)
        finally:
            free(<void*> norm_caps_to_add)
        return len(caps_to_add)


    cpdef drop_caps_from_all_sets(self, caps_to_drop):
        self.drop_caps_from_one_set(caps_to_drop, CAP_INHERITABLE)
        self.drop_caps_from_one_set(caps_to_drop, CAP_EFFECTIVE)
        self.drop_caps_from_one_set(caps_to_drop, CAP_PERMITTED)

    cpdef limit_caps_in_all_sets(self, caps_to_keep):
        self.limit_caps_in_one_set(caps_to_keep, CAP_INHERITABLE)
        self.limit_caps_in_one_set(caps_to_keep, CAP_EFFECTIVE)
        self.limit_caps_in_one_set(caps_to_keep, CAP_PERMITTED)

    cpdef drop_from_bounding_set(self, caps_to_drop):
        caps_to_drop = set(normalize_list_of_caps(caps_to_drop))
        cdef int res
        for i in caps_to_drop:
            res = cap_drop_bound(<cap_value_t> i)
            if res == -1:
                raise RuntimeError("error executing cap_drop_bound(%s)" % i)

    cpdef limit_bounding_set(self, caps_to_keep):
        caps_to_keep = set(normalize_list_of_caps(caps_to_keep))
        current_bounding = set([cap[0] for cap in self.get_bounding_set()])
        caps_to_drop = current_bounding.difference(caps_to_keep)
        self.drop_from_bounding_set(caps_to_drop)


cdef cap_flag_t string_to_flag(capset):
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

cdef normalize_list_of_caps(list_of_caps):
    if list_of_caps is None:
        return []
    if isinstance(list_of_caps, basestring):
        list_of_caps = [list_of_caps]
    list_of_caps = [cap.encode('ascii') if isinstance(cap, unicode) else cap for cap in list_of_caps]
    list_of_caps = [cap.lower().strip() if isinstance(cap, bytes) else cap for cap in list_of_caps]
    return [SUPPORTED_CAPS[cap] if isinstance(cap, bytes) else cap for cap in list_of_caps]

capabilities = Capabilities()

cpdef lockdown_account(uid=None, gid=None, caps_to_keep=None):
    effective_caps = [cap[1] for cap in capabilities.effective]
    permitted_caps = [cap[1] for cap in capabilities.permitted]
    if b"setpcap" not in effective_caps:
        if b"setpcap" not in permitted_caps:
            raise RuntimeError("the current process doesn't have setpcap cap")
        else:
            capabilities.add_caps_to_one_set(b"setfcap", CAP_EFFECTIVE)
    if uid is not None:
        if b'setuid' not in effective_caps:
            if b'setuid' not in permitted_caps:
                raise RuntimeError("the current process doesn't have setuid cap")
            else:
                capabilities.add_caps_to_one_set(b"setuid", CAP_EFFECTIVE)
    if gid is not None:
        if b'setgid' not in effective_caps:
            if b'setgid' not in permitted_caps:
                raise RuntimeError("the current process doesn't have setgid cap")
            else:
                capabilities.add_caps_to_one_set(b"setgid", CAP_EFFECTIVE)

    caps_to_keep = set(normalize_list_of_caps(caps_to_keep))

    set_noroot()
    set_keep_caps()
    set_no_setuid_fixup()
    if gid is not None:
        os.setgid(gid)
    if uid is not None:
        os.setuid(uid)

    inheritable_caps = set([cap[0] for cap in capabilities.inheritable])
    caps_to_add_to_inheritable = caps_to_keep.difference(inheritable_caps)
    capabilities.add_caps_to_one_set(caps_to_add_to_inheritable, CAP_INHERITABLE)

    effective_caps = set([cap[0] for cap in capabilities.effective])
    caps_to_add_to_effective = caps_to_keep.difference(effective_caps)
    capabilities.add_caps_to_one_set(caps_to_add_to_effective, CAP_EFFECTIVE)

    capabilities.add_caps_to_one_set("setpcap", CAP_EFFECTIVE)
    capabilities.limit_bounding_set(caps_to_keep)
    capabilities.limit_caps_in_all_sets(caps_to_keep)

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


cdef get_securebits():
    res = int(prctl(PR_GET_SECUREBITS, 0, 0, 0, 0))
    if res == -1:
        raise RuntimeError("get_securebits() failed")
    return res

cdef set_noroot(locked=True):
    global SECURE_NOROOT_LOCKED, SECURE_NOROOT
    current = get_securebits()
    modified = (current | SECURE_NOROOT_LOCKED | SECURE_NOROOT) if locked else (current | SECURE_NOROOT)
    res = int(prctl(PR_SET_SECUREBITS, <unsigned long> modified, 0, 0, 0))
    if res == -1:
        raise RuntimeError("set_noroot failed")

cdef set_keep_caps(locked=True):
    global SECURE_KEEP_CAPS_LOCKED, SECURE_KEEP_CAPS
    current = get_securebits()
    modified = (current | SECURE_KEEP_CAPS_LOCKED | SECURE_KEEP_CAPS) if locked else (current | SECURE_KEEP_CAPS)
    res = int(prctl(PR_SET_SECUREBITS, <unsigned long> modified, 0, 0, 0))
    if res == -1:
        raise RuntimeError("set_keep_caps failed")

cdef set_no_setuid_fixup(locked=True):
    global SECURE_NO_SETUID_FIXUP_LOCKED, SECURE_NO_SETUID_FIXUP
    current = get_securebits()
    modified = (current | SECURE_NO_SETUID_FIXUP_LOCKED | SECURE_NO_SETUID_FIXUP) if locked else (current | SECURE_NO_SETUID_FIXUP)
    res = int(prctl(PR_SET_SECUREBITS, <unsigned long> modified, 0, 0, 0))
    if res == -1:
        raise RuntimeError("set_no_setuid_fixup failed")


