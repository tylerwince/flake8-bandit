import io
import os
import sys
from shutil import rmtree

from setuptools import setup, Command


def get_version(fname="flake8_bandit.py"):
    with open(fname) as f:
        for line in f:
            if line.startswith("__version__"):
                return eval(line.split("=")[~0])


# Package meta-data.
NAME = "flake8_bandit"
DESCRIPTION = "Automated security testing with bandit and flake8."
URL = "https://github.com/tylerwince/flake8-bandit"
EMAIL = "tyler@myndshft.com"

AUTHOR = "Tyler Wince"

# What packages are required for this module to be executed?
REQUIRED = ["flake8", "bandit"]

here = os.path.abspath(os.path.dirname(__file__))

with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = "\n" + f.read()


class UploadCommand(Command):
    """Support setup.py upload."""

    description = "Build and publish the package."
    user_options = []

    @staticmethod
    def status(s):
        """Print things in bold."""
        print("\033[1m{0}\033[0m".format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status("Removing previous builds...")
            rmtree(os.path.join(here, "dist"))
        except OSError:
            pass

        self.status("Building Source and Wheel (universal) distribution...")
        os.system("{0} setup.py sdist bdist_wheel --universal".format(
            sys.executable))

        self.status("Uploading the package to PyPi via Twine...")
        os.system("twine upload dist/*")

        sys.exit()


setup(
    name=NAME,
    version=get_version(),
    description=DESCRIPTION,
    long_description=long_description,
    author=AUTHOR,
    author_email=EMAIL,
    url=URL,
    py_modules=["flake8_bandit"],
    install_requires=REQUIRED,
    include_package_data=True,
    license="MIT",
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
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
    ],
    cmdclass={
        "upload": UploadCommand,
    }, )
