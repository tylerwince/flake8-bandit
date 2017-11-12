# flake8-bandit

Automated security testing built right into your workflow!

You already use flake8 to lint all your code for errors, ensure docstrings are formatted correctly, sort your imports correctly, and much more... so why not ensure you are writing secure code while you're at it? If you already have flake8 installed all it takes is `pip install flake8-bandit`.

## How's it work?

We use the [bandit](https://github.com/openstack/bandit/blob/master/bandit/cli/main.py) package from [Open Stack](https://www.openstack.org) for all the security testing. This package is simply a flake8 wrapper around their project (similar to [flake8-isort](https://github.com/gforcada/flake8-isort)).
