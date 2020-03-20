#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

meta = {}
exec(open('wrapper/meta.py').read(), meta)

setup(
    name=meta.get('NAME'),
    version=meta.get('VERSION'),
    description=meta.get('DESCRIPTION'),
    long_description=''.join(open('docs/Virt-v2v-wrapper.md').readlines()),
    keywords=meta.get('KEYWORDS'),
    author=meta.get('AUTHOR'),
    author_email=meta.get('EMAIL'),
    license=meta.get('LICENSE'),
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'virt-v2v-wrapper = wrapper.virt_v2v_wrapper:main'
        ]
    },
    install_requires=[
        'pycurl',
        'six',
        'libvirt-python',
        'pyvmomi',
        'packaging',
        # TODO: Uncomment this when it becomes available in pypi and also do
        # the same in Pipfile, add it to requirements.txt and remove the mocked
        # nbd.py
        # 'libnbd-python',
    ],
    extras_require={
        'ovirt': 'ovirt-engine-sdk-python',
        'openstack': 'python-openstackclient',
    },
    # tests_require=[
    #     'tox',
    #     'yamllint',
    #     'flake8',
    #     'pylint',
    # ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ]
)
