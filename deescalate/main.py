# -*- coding: utf-8 -*-

__author__ = 'stephane.martin_github@vesperal.eu'

import os
import platform

from deescalate.cd import py_prctl, C_CapabilitySet, C_BoundingSet
from .constants import C
from .utils import normalize_uid, normalize_gid, normalize_list_of_caps, capset_string_to_flag

is_linux = platform.system().lower().strip().startswith('linux')


class CapabilitySet(C_CapabilitySet):
    """
    Represent a set of capabilities.

    Notes
    -----
    - Usually a CapabilitySet is used directly from one of its instance object (effective, permitted, inheritable).

    - A CapabilitySet is iterable, so to get the capabilities it countains::

        set(effective)

    - To check if a capability is in the set::

        b'net_admin' in effective

    - Arithmetic operators can be used to add/remove capabilities::

        effective -= b'net_admin'
        permitted += b'net_raw'
        inheritable += b'setuid, setgid'
        inheritable -= [b'sys_chroot', b'sys_ptrace']

    References
    ----------
    - `Capabilities manual page <http://man7.org/linux/man-pages/man7/capabilities.7.html>`_
    """
    instances = {}

    def __init__(self, capset):

        super(CapabilitySet, self).__init__(capset)

    def remove_all_except(self, caps_to_keep):
        """
        Remove every capability from the set, except the ones given in `caps_to_keep`.

        Parameters
        ----------
        caps_to_keep: bytes or list of bytes
            Do not drop these capabilities
        """
        caps_to_drop = C.SUPPORTED_CAPS_VALUES.difference(normalize_list_of_caps(caps_to_keep))
        self.__isub__(caps_to_drop)

    def set(self, caps):
        caps_to_keep = normalize_list_of_caps(caps)
        caps_to_clear = C.SUPPORTED_CAPS_VALUES.difference(caps_to_keep)
        self._modify(caps_to_keep, C.FLAG_VALUES[b'set'])
        self._modify(caps_to_clear, C.FLAG_VALUES[b'clear'])

    def __iadd__(self, caps_to_add):
        caps_to_add = normalize_list_of_caps(caps_to_add).difference(set(self))
        self._modify(caps_to_add, C.FLAG_VALUES[b'set'])
        return self

    def __isub__(self, caps_to_drop):
        caps_to_drop = normalize_list_of_caps(caps_to_drop).intersection(set(self))
        self._modify(caps_to_drop, C.FLAG_VALUES[b'clear'])
        return self

    @classmethod
    def get_instance(cls, capset):
        """
        CapabilitySet factory (class method).

        Parameters
        ----------
        capset: int or string
            which capability set to deal with ("effective", "permitted" or "inheritable")
        """
        capset = capset_string_to_flag(capset)
        if capset not in cls.instances:
            cls.instances[capset] = cls(capset)
        return cls.instances[capset]


class BoundingSet(C_BoundingSet):
    """
    Represents the bounding capability set.

    Notes
    -----
    - BoundindSet is iterable::

        list_of_caps = list(bounding_set)

    - To check if a capability is in the bounding set::

        b'net_admin' in bounding_set

    - The BoundingSet just supports removing some capabilities it countains. Use::

        bounding_set -= b'net_admin,mac_override'
        bounding_set -= [b'syslog', b'wake_alarm']
    """
    instance = None

    def __init__(self):
        super(BoundingSet, self).__init__()

    def __isub__(self, caps_to_drop):
        [self._remove_one_cap(i) for i in normalize_list_of_caps(caps_to_drop)]
        return self

    def remove_all_except(self, caps_to_keep):
        caps_to_drop = set(self).difference(normalize_list_of_caps(caps_to_keep))
        self.__isub__(caps_to_drop)

    @classmethod
    def get_instance(cls):
        """
        BoundingSet factory (class method).
        """
        if cls.instance is None:
            cls.instance = cls()
        return cls.instance

permitted = CapabilitySet.get_instance(C.FLAGS[b'permitted'])
"""Permitted capability set"""
inheritable = CapabilitySet.get_instance(C.FLAGS[b'inheritable'])
"""Inheritable capability set"""
effective = CapabilitySet.get_instance(C.FLAGS[b'effective'])
"""Effective capability set"""
bounding_set = BoundingSet.get_instance()
"""Capability bounding set"""


def get_securebits():
    """
    Return the currently defined secure bits

    Returns
    -------
    2uple (the securebits as an int, a dict of securebits)
    """

    res = py_prctl(C.PRCTL[b'get_securebits'], 0, 0, 0, 0)
    if res == -1:
        raise RuntimeError("get_securebits() failed")
    d = {
        'SECBIT_NOROOT': res & C.SECBIT_NOROOT,
        'SECBIT_NOROOT_LOCKED': res & C.SECBIT_NOROOT_LOCKED,
        'SECBIT_KEEP_CAPS': res & C.SECBIT_KEEP_CAPS,
        'SECBIT_KEEP_CAPS_LOCKED': res & C.SECBIT_KEEP_CAPS_LOCKED,
        'SECBIT_NO_SETUID_FIXUP': res & C.SECBIT_NO_SETUID_FIXUP,
        'SECBIT_NO_SETUID_FIXUP_LOCKED': res & C.SECBIT_NO_SETUID_FIXUP_LOCKED
    }
    return res, d


def set_noroot(locked=True):
    """
    Set the `SECBIT_NOROOT` securebit.

    Parameters
    ----------
    locked: bool
        if True, also set `SECBIT_NOROOT_LOCKED`

    Raises
    ------
    RuntimeError
        if operation fails
    """
    current = get_securebits()[0]
    modified = (current | C.SECBIT_NOROOT_LOCKED | C.SECBIT_NOROOT) if locked else (current | C.SECBIT_NOROOT)
    res = py_prctl(C.PRCTL[b'set_securebits'], modified, 0, 0, 0)
    if res == -1:
        raise RuntimeError("set_noroot failed")


def set_keep_caps(locked=True):
    """
    Set the `SECBIT_KEEP_CAPS` securebit.

    Parameters
    ----------
    locked: bool
        if True, also set `SECBIT_KEEP_CAPS_LOCKED`

    Raises
    ------
    RuntimeError
        if operation fails
    """
    current = get_securebits()[0]
    modified = (current | C.SECBIT_KEEP_CAPS_LOCKED | C.SECBIT_KEEP_CAPS) if locked else (current | C.SECBIT_KEEP_CAPS)
    res = py_prctl(C.PRCTL[b'set_securebits'], modified, 0, 0, 0)
    if res == -1:
        raise RuntimeError("set_keep_caps failed")


def set_no_setuid_fixup(locked=True):
    """
    Set the `SECBIT_NO_SETUID_FIXUP` securebit.

    Parameters
    ----------
    locked: bool
        if True, also set `SECBIT_NO_SETUID_FIXUP_LOCKED`

    Raises
    ------
    RuntimeError
        if operation fails
    """
    current = get_securebits()[0]
    modified = (current | C.SECBIT_NO_SETUID_FIXUP_LOCKED | C.SECBIT_NO_SETUID_FIXUP) if locked \
        else (current | C.SECBIT_NO_SETUID_FIXUP)
    res = py_prctl(C.PRCTL[b'set_securebits'], modified, 0, 0, 0)
    if res == -1:
        raise RuntimeError("set_no_setuid_fixup failed")


def lockdown_account(uid=None, gid=None, caps_to_keep=None):
    """
    Deescalate the privileges of the running process.

    `lockdown_account` will:

    - set the secure bits `noroot`, `keep_caps`, `no_setuid_fixup` and their locked companions

    - perform a `setgid` and a `setuid`

    - restrict the 3 cap sets and the bounding set to the list given in `caps_to_keep`

    - set `no_new_privs`

    Parameters
    ----------
    uid: int or string, optional
        switch to this UID
    gid: int or string, optional
        switch to this GID
    caps_to_keep: list of bytes, optional
        a list of capabilities to keep

    Raises
    ------
    RuntimeError
        if some capability operation fails
    OSError
        operation not permitted

    Note
    ----
    When not on Linux, only setgid and setuid will be performed

    Examples
    --------
    >>> lockdown_account('www-data', 'www-data', 'net_bind_service')
    >>> lockdown_account('scapy', 'scapy', ['net_admin', 'net_raw'])
    """
    caps_to_keep = normalize_list_of_caps(caps_to_keep)
    global effective, inheritable, permitted, is_linux
    if is_linux:
        if b"setpcap" not in effective:
            if b"setpcap" not in permitted:
                raise RuntimeError("the current process doesn't have the setpcap capability")
            else:
                effective += b"setpcap"
        if uid is not None:
            if b'setuid' not in effective:
                if b'setuid' not in permitted:
                    raise RuntimeError("the current process doesn't have the setuid capability")
                else:
                    effective += b"setuid"
        if gid is not None:
            if b'setgid' not in effective:
                if b'setgid' not in permitted:
                    raise RuntimeError("the current process doesn't have the setgid capability")
                else:
                    effective += b"setgid"

        set_noroot()
        set_keep_caps()
        set_no_setuid_fixup()

    if uid is not None:
        os.setgid(normalize_gid(uid, gid))
        os.setuid(normalize_uid(uid))

    if is_linux:
        capset = set(permitted).intersection(caps_to_keep)
        effective += b'setpcap'

        bounding_set.remove_all_except(capset)
        inheritable.set(capset)
        effective.set(capset)
        permitted.set(capset)

        set_no_new_privs()


def set_no_new_privs():
    """
    Set `no_new_privs`.

    Notes
    -----
    - With `no_new_privs` set, `execve` promises not to grant the privilege to do anything that could not have been
      done without the `execve` call.

    - See `prctl manual page <http://man7.org/linux/man-pages/man2/prctl.2.html>`_
    """
    py_prctl(C.PRCTL[b'set_no_new_privs'], 1, 0, 0, 0)
