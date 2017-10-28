import os
import json
import pycodestyle
from contextlib import suppress
from bandit.core import config as b_config
from bandit.core import manager as b_manager

__version__ = "v0.1.0"


class BanditTester(object):
    """Flake8 class for checking code for bandit test errors."""

    name = "flake8-bandit"
    version = __version__

    def __init__(self, tree, filename):
        self.filename = filename
        self.tree = tree
        self._load_source()

    def _check_source(self):
        b_conf = b_config.BanditConfig()
        b_mgr = b_manager.BanditManager(b_conf, 'file', False)
        # it is happening here
        b_mgr.discover_files([self.filename])
        b_mgr.run_tests()
        out_file = open("jsonout.json", "w+")
        b_mgr.output_results(3, 'UNDEFINED', 'UNDEFINED', out_file, 'json')
        with open("jsonout.json", "r") as f:
            output = json.load(f)
        os.remove("jsonout.json")
        with suppress(FileNotFoundError):
            os.remove("tempbanditpythonfile.py")
        return output

    def run(self):
        """Use to run the check."""
        for error in self._check_source()["results"]:
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
