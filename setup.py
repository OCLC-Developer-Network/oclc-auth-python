#!/usr/bin/env python

from distutils.core import setup

setup(
    name = 'authliboclc',
    packages = ['authliboclc'],
    version = "0.0.1",
    description = "OCLC API Authentication Library",
    author = 'OCLC Platform Team',
    author_email = "devnet@oclc.org",
    url = 'http://oclc.org/developer/home.en.html',
    download_url = 'git@github.com:OCLC-Developer-Network/oclc-auth-python.git',
    install_requires = ['six>=1']
)