#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages, Extension
import os
import platform
import sys
from distutils.log import info
import subprocess
from os.path import dirname, abspath, join, commonprefix, exists

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))

if __name__ == "__main__":
    if not sys.platform.startswith('linux'):
        sys.stderr.write("This module only works on linux\n")
        sys.exit(1)

    if sys.version_info[:2] < (2, 7):
        sys.stderr.write("This module requires python 2.7 or newer\n")
        sys.exit(1)

    kernel = [int(x) for x in os.uname()[2].split('.')]
    if kernel < [3, 5]:
        sys.stderr.write("This module requires linux kernel 3.5 or newer\n")
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
        # utility module to make python memoryviews from char* buffers
        deescalate_extension = Extension(
            name="deescalate._deescalate",
            sources=["deescalate/_deescalate.pyx"],
            libraries=["cap"]
        )
        extensions.append(deescalate_extension)

    data_files = []

    setup(
        name='deescalate',
        version='0.1',
        description='using linux capabilities to drop privileges in python',
        long_description=readme + '\n\n' + history,
        author='Stephane Martin',
        author_email='stephane.martin_github@vesperal.eu',
        url='https://github.com/stephane-martin/deescalate',
        packages=find_packages(exclude=['tests']),
        setup_requires=[
            'setuptools_git', 'setuptools', 'twine', 'wheel', 'cython'
        ],
        include_package_data=True,
        exclude_package_data={'': ['*.c', '*.cpp', '*.h']},
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
            'console_scripts': []
        },

        data_files=data_files,
        test_suite='tests',
        tests_require=test_requirements,
        ext_modules=extensions

    )
