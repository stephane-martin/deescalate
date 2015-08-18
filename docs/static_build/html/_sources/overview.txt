========
Overview
========

Do we really need full root power just to bind a HTTP server to port 80 ?

On Linux, no. With the capabilities system, a process can be given some special rights even if it's
not running under root.

The deescalate module provides a few functions to manipulate capabilities and to drop unneeded rights. This way,
your python coded server can be ran as root, but drop everything it does not need as soon as it can.

But dropping capabilities in not the end of the story: if we still run the program as root, some dangerous exploits
remain: for example, the program will still be able to access files owned by root (think about crontab). More over,
after an execve, the program could again have access to some dropped capabilities.

The "securebits" stop this: after setting the securebits, the program won't be able to gain full root rights again.
Setting a new uid further enhances the protection.

Finally, since Linux kernel 3.5, a process can set the "no_new_privs" setting to ask the kernel not to ever add some
rights to the process.

All these steps are available with a single call to `deescalate` `lockdown_account` function.

Note
----
The capabilities mechanism just exists on Linux. To ease deployment, `deescalate` will also compile under BSD and
MacOSX, but of course will not do anything particular. Then `lockdown_account` just performs and setuid and setgid.
