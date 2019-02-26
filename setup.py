#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages, Extension
import os
import platform
import sys
import subprocess
from os.path import dirname, abspath, join, commonprefix, exists

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))

def check_gcc():
    try:
        subprocess.call(['gcc', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return False
    return True

def check_prctl():
    sp = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sp.communicate(b'#include <sys/prctl.h>\n')
    return sp.returncode == 0

def check_lipcap():
    sp = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sp.communicate(b'#include <sys/capability.h>\n')
    return sp.returncode == 0

def get_kernel_version():
    kernel_version = platform.uname()[2]
    kernel_version = kernel_version.split('-')[0]
    kernel_version = kernel_version.split('.')
    return [int(i) for i in kernel_version]

def check_kernel_version():
    return get_kernel_version() >= [3, 5]

def check_python_version():
    return sys.version_info[:2] >= (2, 7)

if __name__ == "__main__":
    dummy = False
    # on readthedocs, we don't check prerequisites
    if not on_rtd:
        if not platform.system().lower().startswith('linux'):
            # not linux
            sys.stderr.write("\nThis module only works on linux. Just compiling dummy module.\n\n")
            dummy = True
            if not check_gcc():
                sys.stderr.write("You need to install gcc to build this module\n")
                sys.exit(1)
        else:
            # linux
            if not check_kernel_version():
                # kernel not recent enough
                sys.stderr.write("This module requires linux kernel 3.5 or newer\n")
                sys.exit(1)
            else:
                # good kernel version
                if not check_gcc():
                    sys.stderr.write("You need to install gcc to build this module\n")
                    sys.exit(1)
                if not check_prctl():
                    sys.stderr.write("You need to install libc development headers (eg libc6-dev)")
                    sys.exit(1)
                if not check_lipcap():
                    sys.stderr.write("You need to install libcap development headers (eg libcap-dev)")
                    sys.exit(1)

        if not check_python_version():
            sys.stderr.write("This module requires python 2.7 or newer\n")
            sys.exit(1)

    with open('README.rst') as readme_file:
        readme = readme_file.read()

    with open('HISTORY.rst') as history_file:
        history = history_file.read().replace('.. :changelog:', '')

    requirements = []
    remove_requirements_if_rtd = []

    if on_rtd:
        for ext in remove_requirements_if_rtd:
            requirements.remove(ext)

    test_requirements = []
    extensions = []
    if not on_rtd:
        deescalate_extension = Extension(
            name="deescalate.cd",
            sources=["deescalate/cd.pyx"],
            libraries=["cap"] if not dummy else []
        )
        extensions.append(deescalate_extension)

    data_files = []

    setup(
        name='deescalate',
        version='0.1.2',
        description='using linux capabilities to drop privileges in python',
        long_description=readme + '\n\n' + history,
        author='Stephane Martin',
        author_email='stephane.martin_github@vesperal.eu',
        url='https://github.com/stephane-martin/deescalate',
        packages=find_packages(exclude=['tests']),
        setup_requires=[
            'setuptools_git', 'setuptools', 'twine', 'wheel', 'Cython'
        ],
        include_package_data=True,
        exclude_package_data={'': ['*.c', '*.cpp', '*.h', '*.html', '*.txt']},
        install_requires=requirements,
        license="LGPLv3+",
        zip_safe=False,
        keywords='linux cython python capabilities root prctl securebits privileges',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
            'Natural Language :: English',
            'Programming Language :: Python :: 2.7',
            'Environment :: Console',
            'Operating System :: POSIX :: Linux'
        ],
        entry_points={
            'console_scripts': [
                'deescalate = deescalate.script:main'
            ]
        },

        data_files=data_files,
        test_suite='tests',
        tests_require=test_requirements,
        ext_modules=extensions
    )
