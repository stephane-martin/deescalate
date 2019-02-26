# -*- coding: utf-8 -*-

from libc.stdlib cimport malloc, free
from .constants import C
from .utils import capset_string_to_flag

IF UNAME_SYSNAME == "Linux":

    cdef update_constants():

        C.FLAGS.update({
            b'effective': CAP_EFFECTIVE,
            b'permitted': CAP_PERMITTED,
            b'inheritable': CAP_INHERITABLE
        })

        C.FLAG_VALUES.update({
            b'clear': CAP_CLEAR,
            b'set': CAP_SET
        })

        C.PRCTL.update({
            b'get_securebits': PR_GET_SECUREBITS,
            b'set_securebits': PR_SET_SECUREBITS,
            b'set_no_new_privs': PR_SET_NO_NEW_PRIVS,
            b'get_no_new_privs': PR_GET_NO_NEW_PRIVS
        })

        C.SUPPORTED_CAPS.clear()
        C.UNSUPPORTED_CAPS[:] = []
        cdef char* temp
        for i in range(CAP_LAST_CAP + 1):
            if CAP_IS_SUPPORTED(<cap_value_t> i) == 1:
                temp = cap_to_name(<cap_value_t> i)
                if temp != NULL:
                    cap_name = (<bytes>temp).lower()
                    cap_free(<void*> temp)
                    if cap_name and not cap_name.isdigit():
                        cap_name = cap_name[4:]
                        C.SUPPORTED_CAPS[cap_name] = i
                        C.INVERSE_SUPPORTED_CAPS[i] = cap_name
                    else:
                        if i <= (C.NB_HARD_CODED - 1):
                            C.UNSUPPORTED_CAPS.append(C.HARD_CODED_CAPS[i])
                        else:
                            C.UNSUPPORTED_CAPS.append(str(i))

        C.SUPPORTED_CAPS_NAMES = set(C.SUPPORTED_CAPS.keys())
        C.SUPPORTED_CAPS_VALUES = set(C.SUPPORTED_CAPS.values())

    update_constants()


    cdef class C_CapabilitySet(object):
        def __init__(self, capset):
            capset = capset_string_to_flag(capset)
            self.flag = <cap_flag_t> capset

        def __iter__(self):
            cdef cap_flag_value_t flag_value
            cdef int res
            cdef cap_t current = cap_get_proc()
            if <void*>current != NULL:
                try:
                    for i in C.SUPPORTED_CAPS_VALUES:
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
            cdef cap_value_t cap = <cap_value_t> item if isinstance(item, int) else <cap_value_t> C.SUPPORTED_CAPS[bytes(item)]
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

        cpdef _modify(self, caps_to_modify, flag_value):
            if len(caps_to_modify) == 0:
                return 0
            cdef cap_value_t* norm_caps_to_modify = <cap_value_t*> malloc(len(caps_to_modify) * sizeof(cap_value_t))
            cdef cap_t current
            try:
                current = cap_get_proc()
                try:
                    for idx, i in enumerate(caps_to_modify):
                        norm_caps_to_modify[idx] = <cap_value_t> i
                    res = cap_set_flag(current, self.flag, len(caps_to_modify), norm_caps_to_modify, <cap_flag_value_t> flag_value)
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

    cdef class C_BoundingSet(object):
        def __init__(self):
            pass

        def __iter__(self):
            for i in C.SUPPORTED_CAPS_VALUES:
                if cap_get_bound(<cap_value_t> i) == CAP_SET:
                    yield i

        def __contains__(self, item):
            cdef cap_value_t cap = <cap_value_t> item if isinstance(item, int) else <cap_value_t> C.SUPPORTED_CAPS[bytes(item)]
            return cap_get_bound(<cap_value_t> cap) == CAP_SET

        cpdef _remove_one_cap(self, int cap):
            cdef int res = cap_drop_bound(<cap_value_t> cap)
            if res == -1:
                raise RuntimeError("error executing cap_drop_bound(%s)" % cap)

    cpdef py_prctl(option, arg2, arg3, arg4, arg5):
        res = int(prctl(<int> option, <unsigned long> arg2, <unsigned long> arg3, <unsigned long> arg4, <unsigned long> arg5))
        if res < 0:
            raise RuntimeError
        return res

ELSE:

    # fake module so that we can compile and build documentation on mac osx
    cdef class C_BoundingSet(object):
        def __init__(self):
            pass
        cpdef _remove_one_cap(self, int cap):
            pass
        def __iter__(self):
            return (x for x in [])
        def __contains__(self, item):
            return False

    cpdef py_prctl(option, arg2, arg3, arg4, arg5):
        return 0

    cdef class C_CapabilitySet(object):
        def __init__(self, capset):
            pass
        cpdef _modify(self, caps_to_modify, flag_value):
            pass
        def __iter__(self):
            return (x for x in [])
        def __contains__(self, item):
            return False

