# -*- coding: utf-8 -*-

IF UNAME_SYSNAME == "Linux":

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
        int     CAP_IS_SUPPORTED(cap_value_t cap)
        cap_t   cap_from_text(const char *)
        char *  cap_to_text(cap_t, ssize_t *)
        int     cap_from_name(const char *, cap_value_t *)
        char *  cap_to_name(cap_value_t)
        int     cap_compare(cap_t, cap_t)

ELSE:
    ctypedef enum cap_flag_value_t:
        CAP_CLEAR,
        CAP_SET
    ctypedef enum cap_flag_t:
        CAP_EFFECTIVE,
        CAP_PERMITTED,
        CAP_INHERITABLE
    ctypedef int cap_value_t



cpdef lockdown_account(uid=?, gid=?, caps_to_keep=?)
cpdef get_securebits()
cpdef set_noroot(locked=?)
cpdef set_keep_caps(locked=?)
cpdef set_no_setuid_fixup(locked=?)




