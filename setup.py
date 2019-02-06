#!/usr/bin/env python

from setuptools import setup

setup(
    name = 'authliboclc',
    packages = ['authliboclc'],
    version = "0.0.2",
    license='Apache2',
    description = "OCLC API Authentication Library",
    author = 'OCLC Platform Team',
    author_email = "devnet@oclc.org",
    url = 'http://oclc.org/developer/home.en.html',
    download_url = 'git@github.com:OCLC-Developer-Network/oclc-auth-python.git',
    install_requires = ['six>=1']
)
