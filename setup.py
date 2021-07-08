#!/usr/bin/env python
from __future__ import print_function

from setuptools import find_packages, setup

import yowsup_config

deps = ['consonance==0.1.3-1', 'argparse', 'python-axolotl==0.2.2', 'six==1.10', 'appdirs', 'protobuf>=3.6.0']

setup(
    name='yowsup-config-extracter',
    version=yowsup_config.__version__,
    url='http://github.com/kaisar945/yowsup-config-extracter/',
    license='GPL-3+',
    author='Kaisar Zu',
    tests_require=[],
    install_requires=deps,
    scripts=['yowsup-config-extract'],
    # cmdclass={'test': PyTest},
    author_email='jiankaihu.jrsen@gmail.com',
    description='The WhatsApp tool lib',
    # long_description=long_description,
    packages=find_packages(),
    include_package_data=True,
    data_files=[('yowsup_config/common', ['yowsup_config/common/mcc-mnc-table.json'])],
    platforms='any',
    # test_suite='',
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        # 'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
