# -*- coding: utf-8 -*-
"""Implementation of bandit security testing in Flake8.

Bandit is a security linter for python code and needs to be installed
for this flake8 extension to work properly.
"""
import os
import tempfile

import pycodestyle
from bandit.core import config
from bandit.core import manager
from flake8_polyfill import stdin

__version__ = "v2.0.0"

stdin.monkey_patch("pycodestyle")


class BanditTester(object):
    """Flake8 class for checking code for bandit test errors.

    This class is necessary and used by flake8 to check the python
    file or files that are being tested.

    """

    name = "flake8-bandit"
    version = __version__

    def __init__(self, tree, filename):  # tree is required by flake8
        self.filename = filename
        self._load_source()

    def _check_source(self):
        mgr = manager.BanditManager(config.BanditConfig(), "file", False)
        mgr.discover_files([self.filename])
        mgr.run_tests()
        issues = []
        for item in mgr.get_issue_list():
            issues.append(
                {
                    "test_id": item.test_id.replace("B", "S"),
                    "issue_text": item.text,
                    "line_number": item.lineno,
                }
            )
        if self.tmpfile:
            os.remove(self.filename)
        return issues

    def run(self):
        """run will check file source through the bandit code linter."""
        for error in self._check_source():
            message = "%s %s" % (error["test_id"], error["issue_text"])
            yield (error["line_number"], 0, message, type(self))

    def _load_source(self):
        if self.filename in ("stdin", "-", None):
            self.source = pycodestyle.stdin_get_value()
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                f.write(self.source)
                self.filename = f.name
                self.tmpfile = True
            return
        with open(self.filename) as f:
            self.source = f.read()
            self.tmpfile = False
