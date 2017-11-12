# -*- coding: utf-8 -*-
"""Implementation of bandit security testing in Flake8.

Bandit is a security linter for python code and needs to be installed
for this flake8 extension to work properly.
"""
import os

import pycodestyle
from bandit.core import config as b_config
from bandit.core import manager as b_manager
from flake8_polyfill import stdin

__version__ = "v0.2.0"

stdin.monkey_patch('pycodestyle')


class BanditTester(object):
    """Flake8 class for checking code for bandit test errors.

    This class is necessary and used by flake8 to check the python
    file or files that are being tested.

    """

    name = "flake8-bandit"
    version = __version__

    def __init__(self, tree, filename):
        """Initialize all the necessary attributes for flake8."""
        self.filename = filename
        self.tree = tree
        self._load_source()

    def _check_source(self):
        b_conf = b_config.BanditConfig()
        b_mgr = b_manager.BanditManager(b_conf, 'file', False)
        # it is happening here
        b_mgr.discover_files([self.filename])
        b_mgr.run_tests()
        issues = []
        for item in b_mgr.get_issue_list():
            i = {}
            i["test_id"] = item.test_id
            i["issue_text"] = item.text
            i["line_number"] = item.lineno
            issues.append(i)
        os.remove("tempbanditpythonfile.py")
        return issues

    def run(self):
        """Use to run the check."""
        for error in self._check_source():
            message = "%s %s" % (error["test_id"], error["issue_text"])
            yield (error["line_number"], 0, message, type(self))

    def _load_source(self):
        """Load the source for the specified file."""
        if self.filename == "stdin":
            self.source = pycodestyle.stdin_get_value()
            with open("tempbanditpythonfile.py", "w+") as f:
                f.write(self.source)
            self.filename = "tempbanditpythonfile.py"
        else:
            with open(self.filename) as f:
                self.source = f.read()
