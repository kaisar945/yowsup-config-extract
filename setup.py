#!/usr/bin/env python
from __future__ import print_function

from setuptools import find_packages, setup

import yowsup_config

deps = ['argparse']

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
    description='The WhatsApp config extract tool lib',
    # long_description=long_description,
    packages=find_packages(),
    include_package_data=True,
    data_files=[('yowsup_config/common', ['yowsup_config/common/mcc-mnc-table.json', 'yowsup_config/common/decrypt.dex'])],
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
