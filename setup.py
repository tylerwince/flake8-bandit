# -*- coding: utf-8 -*-

import os

from setuptools import setup


def get_version(fname="flake8_bandit.py"):
    with open(fname) as f:
        for line in f:
            if line.startswith("__version__"):
                return eval(line.split("=")[~0])


# Package meta-data.
NAME = 'flake8_bandit'
DESCRIPTION = 'Automated Bandit testing using flake8.'
long_description = "Automate Bandit testing using flake8."
URL = 'https://github.com/tylerwince/flake8-bandit'
EMAIL = 'tyler@myndshft.com'
AUTHOR = 'Tyler Wince'

# What packages are required for this module to be executed?
REQUIRED = [
    'flake8'
]

here = os.path.abspath(os.path.dirname(__file__))

setup(
    name=NAME,
    version=get_version(),
    description=DESCRIPTION,
    long_description=long_description,
    author=AUTHOR,
    author_email=EMAIL,
    url=URL,
    py_modules=['mypackage'],
    install_requires=REQUIRED,
    include_package_data=True,
    license='MIT',
    entry_points={
            "flake8.extension": [
                "B=flake8_bandit:BanditTester",
            ],
        },
    classifiers=[
        "Framework :: Flake8",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
