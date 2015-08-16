# -*- coding: utf-8 -*-

cdef extern from "sys/types.h" nogil:
    ctypedef unsigned int pid_t

cdef extern from "sys/prctl.h" nogil:
    int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
    int PR_GET_SECUREBITS, PR_SET_SECUREBITS, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS


cdef extern from "sys/capability.h" nogil:
    ctypedef enum cap_flag_t:
        CAP_EFFECTIVE,
        CAP_PERMITTED,
        CAP_INHERITABLE
    ctypedef enum cap_flag_value_t:
        CAP_CLEAR,
        CAP_SET
    ctypedef int cap_value_t
    ctypedef struct cap_t:
        pass

    int CAP_LAST_CAP
    int cap_valid(int)
    int CAP_TO_INDEX(int)
    int CAP_TO_MASK(int)

    int     cap_free(void *)
    cap_t   cap_init()
    int     cap_get_flag(cap_t, cap_value_t, cap_flag_t, cap_flag_value_t *)
    int     cap_set_flag(cap_t, cap_flag_t, int, const cap_value_t *, cap_flag_value_t)
    int     cap_clear(cap_t)
    int     cap_clear_flag(cap_t, cap_flag_t)
    cap_t   cap_get_fd(int)
    cap_t   cap_get_file(const char *)
    int     cap_set_fd(int, cap_t)
    int     cap_set_file(const char *, cap_t)
    cap_t   cap_get_proc()
    cap_t   cap_get_pid(pid_t)
    int     cap_set_proc(cap_t)
    int     cap_get_bound(cap_value_t)
    int     cap_drop_bound(cap_value_t)
    int     CAP_IS_SUPPORTED(cap)
    cap_t   cap_from_text(const char *)
    char *  cap_to_text(cap_t, ssize_t *)
    int     cap_from_name(const char *, cap_value_t *)
    char *  cap_to_name(cap_value_t)
    int     cap_compare(cap_t, cap_t)


cdef class Capabilities(object):
    cpdef get_caps_in_set(self, capset)
    cpdef get_bounding_set(self)
    cpdef limit_caps_in_one_set(self, caps_to_keep, capset)
    cpdef drop_caps_from_one_set(self, caps_to_drop, capset)
    cpdef add_caps_to_one_set(self, caps_to_add, capset)
    cpdef drop_caps_from_all_sets(self, caps_to_drop)
    cpdef limit_caps_in_all_sets(self, caps_to_keep)
    cpdef drop_from_bounding_set(self, caps_to_drop)
    cpdef limit_bounding_set(self, caps_to_keep)

cpdef lockdown_account(uid=None, gid=None, caps_to_keep=None)



SECURE_NOROOT = 1 << 0
SECURE_NOROOT_LOCKED = 1 << 1
SECURE_NO_SETUID_FIXUP = 1 << 2
SECURE_NO_SETUID_FIXUP_LOCKED = 1 << 3
SECURE_KEEP_CAPS = 1 << 4
SECURE_KEEP_CAPS_LOCKED = 1 << 5

