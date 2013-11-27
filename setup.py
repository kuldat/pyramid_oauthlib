#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import os, multiprocessing

try:
    import multiprocessing
except ImportError:
    pass

from email.utils import parseaddr
import pyramid_oauthlib

author, author_email = parseaddr(pyramid_oauthlib.__author__)

here = os.path.abspath(os.path.dirname(__file__))
try:
    README = open(os.path.join(here, 'README.rst')).read()
except IOError:
    README = ''

setup(
    name='Pyramid-OAuthlib',
    version=pyramid_oauthlib.__version__,
    author=author,
    author_email=author_email,
    url=pyramid_oauthlib.__homepage__,
    packages=find_packages(),
    description="OAuthlib for Pyramid",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    long_description=README,
    license='MIT',
    install_requires=[
        'Pyramid',
        'oauthlib>=0.6',
    ],
    tests_require=['nose', 'mock'],
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
