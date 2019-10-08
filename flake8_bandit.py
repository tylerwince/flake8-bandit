"""Implementation of bandit security testing in Flake8."""
import ast

import pycodestyle
from flake8.options.config import ConfigFileFinder

from bandit.core.config import BanditConfig
from bandit.core.meta_ast import BanditMetaAst
from bandit.core.metrics import Metrics
from bandit.core.node_visitor import BanditNodeVisitor
from bandit.core.test_set import BanditTestSet

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

try:
    from flake8.engine import pep8 as stdin_utils
except ImportError:
    from flake8 import utils as stdin_utils


__version__ = "2.1.2"


class BanditTester(object):
    """Flake8 class for checking code for bandit test errors.

    This class is necessary and used by flake8 to check the python
    file or files that are being tested.

    """

    name = "flake8-bandit"
    version = __version__

    def __init__(self, tree, filename, lines):
        self.filename = filename
        self.tree = tree
        self.lines = lines

    def _check_source(self):
        ini_file = ConfigFileFinder("bandit", None, None).local_config_files()
        config = configparser.ConfigParser()
        try:
            config.read(ini_file)
            profile = {k: v.replace("S", "B") for k, v in config.items("bandit")}
            if profile.get("skips"):
                profile["exclude"] = profile.get("skips").split(",")
            if profile.get("tests"):
                profile["include"] = profile.get("tests").split(",")
        except (configparser.Error, KeyError, TypeError) as e:
            if str(e) != "No section: 'bandit'":
                import sys
                err = "Unable to parse config file: %s\n" % e
                sys.stderr.write(err)
            profile = {}
        bnv = BanditNodeVisitor(
            self.filename,
            BanditMetaAst(),
            BanditTestSet(BanditConfig(), profile=profile),
            False,
            [],
            Metrics(),
        )
        bnv.generic_visit(self.tree)
        return [
            {
                # flake8-bugbear uses bandit default prefix 'B'
                # so this plugin replaces the 'B' with an 'S' for Security
                # See https://github.com/PyCQA/flake8-bugbear/issues/37
                "test_id": item.test_id.replace("B", "S"),
                "issue_text": item.text,
                "line_number": item.lineno,
            }
            for item in bnv.tester.results
        ]

    def run(self):
        """run will check file source through the bandit code linter."""

        if not self.tree or not self.lines:
            self._load_source()
        for warn in self._check_source():
            message = "%s %s" % (warn["test_id"], warn["issue_text"])
            yield (warn["line_number"], 0, message, type(self))

    def _load_source(self):
        """Loads the file in a way that auto-detects source encoding and deals
        with broken terminal encodings for stdin.

        Stolen from flake8_import_order because it's good.
        """

        if self.filename in ("stdin", "-", None):
            self.filename = "stdin"
            self.lines = stdin_utils.stdin_get_value().splitlines(True)
        else:
            self.lines = pycodestyle.readlines(self.filename)
        if not self.tree:
            self.tree = ast.parse("".join(self.lines))
