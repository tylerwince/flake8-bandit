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


__version__ = "2.1.1"


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

    @classmethod
    def add_options(cls, parser):
        parser.add_option(
            "--skips",
            parse_from_config=True,
            help="Bandit tests to skip.",
            comma_separated_list=True,
        )

        parser.add_option(
            "--tests",
            parse_from_config=True,
            help="Bandit tests to run.",
            comma_separated_list=True,
        )

    @classmethod
    def parse_options(cls, options):
        cls.skips = options.skips
        cls.tests = options.tests

    def _create_profile(self):
        if self.skips or self.tests and not (self.skips and self.tests):
            # FIXME works but I need to find a way to replace the S with a B here
            return {"exclude": self.skips} if self.skips else {"include": self.tests}
        ini_file = ConfigFileFinder("bandit", None, None).local_config_files()
        config = configparser.ConfigParser()
        try:
            config.read(ini_file)
            t = {
                # FIXME I hate this double replace, but just checking functionality
                k.replace("tests", "include").replace("skips", "exclude"): v.replace(
                    "S", "B"
                )
                for k, v in config.items("bandit")
            }
            return t
        except (configparser.Error, KeyError, TypeError) as e:
            if str(e) != "No section: 'bandit'":
                import sys

                sys.stderr.write("Unable to parse config file: %s\n" % e)
            return {}

    def _check_source(self):
        bnv = BanditNodeVisitor(
            self.filename,
            BanditMetaAst(),
            BanditTestSet(BanditConfig(), profile=self._create_profile()),
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
            self.lines = pycodestyle.stdin_get_value().splitlines(True)
        else:
            self.lines = pycodestyle.readlines(self.filename)
        if not self.tree:
            self.tree = ast.parse("".join(self.lines))
