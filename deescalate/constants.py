# -*- coding: utf-8 -*-

__author__ = 'stephane.martin_github@vesperal.eu'

class C(object):
    """
    Gather the various constants used by deescalate.
    """
    #: List of usual capabilities on Linux
    HARD_CODED_CAPS = [
        b'chown', b'dac_override', b'dac_read_search', b'fowner', b'fsetid', b'kill', b'setgid',
        b'setuid', b'setpcap', b'linux_immutable', b'net_bind_service', b'net_broadcast', b'net_admin',
        b'net_raw', b'ipc_lock', b'ipc_owner', b'sys_module', b'sys_rawio', b'sys_chroot', b'sys_ptrace',
        b'sys_pacct', b'sys_admin', b'sys_boot', b'sys_nice', b'sys_resource', b'sys_time', b'sys_tty_config',
        b'mknod', b'lease', b'audit_write', b'audit_control', b'setfcap', b'mac_override', b'mac_admin',
        b'syslog', b'wake_alarm', b'block_suspend'
    ]

    #: number of caps in HARD_CODED_CAPS
    NB_HARD_CODED = len(HARD_CODED_CAPS)

    #: NOROOT securebit
    SECBIT_NOROOT = 1 << 0
    #: NOROOT_LOCKED securebit
    SECBIT_NOROOT_LOCKED = 1 << 1
    #: NO_SETUID_FIXUP securebit
    SECBIT_NO_SETUID_FIXUP = 1 << 2
    #: NO_SETUID_FIXUP_LOCKED securebit
    SECBIT_NO_SETUID_FIXUP_LOCKED = 1 << 3
    #: SECBIT_KEEP_CAPS securebit
    SECBIT_KEEP_CAPS = 1 << 4
    #: SECBIT_KEEP_CAPS_LOCKED securebit
    SECBIT_KEEP_CAPS_LOCKED = 1 << 5

    #: capabilities supported by the running platform
    SUPPORTED_CAPS = {}
    INVERSE_SUPPORTED_CAPS = {}
    SUPPORTED_CAPS_NAMES = set()
    #: capabilities not supported by the running platform
    UNSUPPORTED_CAPS = [] + HARD_CODED_CAPS
    SUPPORTED_CAPS_VALUES = set()

    # type of capability sets
    FLAGS = {b'permitted': 1, b'inheritable': 2, b'effective': 0}
    # possible values for each capability
    FLAG_VALUES = {b'clear': 0, b'set': 1}
    PRCTL = {}
