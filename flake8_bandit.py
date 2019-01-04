# -*- coding: utf-8 -*-
"""Implementation of bandit security testing in Flake8.

Bandit is a security linter for python code and needs to be installed
for this flake8 extension to work properly.
"""
import ast

import pycodestyle
from bandit.core.node_visitor import BanditNodeVisitor
from bandit.core.test_set import BanditTestSet
from bandit.core.config import BanditConfig
from bandit.core.metrics import Metrics
from bandit.core.meta_ast import BanditMetaAst
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

    def __init__(self, tree, filename, lines):  # tree is required by flake8
        self.filename = filename
        self.tree = tree
        self.lines = lines

    def _check_source(self):
        bnv = BanditNodeVisitor(self.filename, BanditMetaAst(), BanditTestSet(BanditConfig(), None), True, [], Metrics())
        bnv.generic_visit(self.tree)
        issues = []
        for item in bnv.tester.results:
            issues.append(
                {
                    "test_id": item.test_id.replace("B", "S"),
                    "issue_text": item.text,
                    "line_number": item.lineno,
                }
            )
        return issues

    def run(self):
        """run will check file source through the bandit code linter."""
        if not self.tree or not self.lines:
            self._load_source()
        for error in self._check_source():
            message = "%s %s" % (error["test_id"], error["issue_text"])
            yield (error["line_number"], 0, message, type(self))

    def _load_source(self):
        """Loads the file in a way that auto-detects source encoding and deals
        with broken terminal encodings for stdin.

        Stolen from flake8_import_order because it's good.
        """

        if self.filename in ("stdin", "-", None):
            self.filename = "stdin"
            self.lines = pycodestyle.stdin_get_value().splitlines(True)
        else:
            self.lines = pycodestyle.readlines(self.filename)

        if not self.tree:
            self.tree = ast.parse("".join(self.lines))
