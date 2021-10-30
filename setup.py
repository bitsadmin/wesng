#!/usr/bin/env python3

from setuptools import setup
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='wesng',
    version='1.0.2.1',
    description='WES-NG is a tool based on the output of Windows\' systeminfo'
    ' utility which provides the list of vulnerabilities the OS is vulnerable'
    ' to, including any exploits for these vulnerabilities.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/bitsadmin/wesng',
    author='Arris Huijgen (@bitsadmin)',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    py_modules=['wes', 'muc_lookup'],
    python_requires='>=3.4, >=2.7',
    install_requires=[],
    package_data={
        'definitions': ['definitions.zip']
    },
    entry_points={
        'console_scripts': [
            'wes=wes:main',
        ],
    },
    project_urls={  # Optional
        'Bug Reports': 'https://github.com/bitsadmin/wesng/issues',
        'Source': 'https://github.com/bitsadmin/wesng/',
    },
)
