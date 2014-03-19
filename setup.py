#!/usr/bin/env python

from distutils.core import setup

setup(
    name = "authliboclc",
    packages = ["authliboclc"],
    version = "0.0.1",
    description = "OCLC API Authentication Library",
    author = "George Campbell",
    author_email = "campbelg@oclc.org",
    url = "http://oclc.org/developer/webservices",
    download_url = "git@github.com:OCLC-Developer-Network/oclc-auth-python.git",
    keywords = ["hmac", "wskey", "oclc", "api", "authentication", "auth"],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Development Status :: 4 - Beta",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "License :: Apache License v2.0",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
    long_description = """\
OCLC Authentication Library
-------------------------------------
Provides authentication utilities for OCLC APIs

This version requires Python 2.
"""
)