from pathlib import Path
from flake8_bandit import BanditTester

import pytest


def _get_errors(filename):
    filename = Path(__file__).absolute().parent / filename
    bt = BanditTester(tree=None, filename=str(filename), lines=None)
    return list(bt.run())


@pytest.mark.parametrize(
    "filename,line,message",
    [
        pytest.param(
            "assert.py",
            [1],
            [
                "S101 Use of assert detected. The enclosed code will be removed when compiling to optimised byte code."
            ],
            id="S101",
        ),
        pytest.param(
            "binding.py", [4], ["S104 Possible binding to all interfaces."], id="S104"
        ),
        pytest.param(
            "cipher-modes.py",
            [6],
            [
                "S305 Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB."
            ],
            id="S305",
        ),
        pytest.param(
            "ciphers.py",
            [1],
            [
                "S413 The pyCrypto library and its module ARC2 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library."
            ],
            id="S413",
        ),
        pytest.param(
            "dill.py",
            [1],
            [
                "S403 Consider possible security implications associated with dill module."
            ],
            id="S403",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            [12],
            ["S610 Use of extra potential SQL attack vector."],
            id="S610",
        ),
        pytest.param(
            "django_sql_injection_raw.py",
            [5],
            ["S611 Use of RawSQL potential SQL attack vector."],
            id="S611",
        ),
        pytest.param(
            "eval.py",
            [3],
            [
                "S307 Use of possibly insecure function - consider using safer ast.literal_eval."
            ],
            id="S307",
        ),
        # [pytest.param("exec-py2.py"], [, "", id="")],
        pytest.param("exec-py3.py", [1], ["S102 Use of exec detected."], id="S102"),
        pytest.param(
            "flask_debug.py",
            [10],
            [
                "S201 A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code."
            ],
            id="S201",
        ),
        pytest.param(
            "ftplib.py",
            [1],
            [
                "S402 A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol."
            ],
            id="S402",
        ),
        pytest.param(
            "hardcoded-passwords.py",
            [1],
            ["S107 Possible hardcoded password: 'Admin'"],
            id="S107",
        ),
        pytest.param(
            "hardcoded-tmp.py",
            [1],
            ["S108 Probable insecure usage of temp file/directory."],
            id="S108",
        ),
        pytest.param(
            "hashlib_new_insecure_functions.py",
            [3],
            ["S324 Use of insecure MD4 or MD5 hash function."],
            id="S324",
        ),
        pytest.param(
            "httplib_https.py",
            [2],
            [
                "S309 Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033"
            ],
            id="S309",
        ),
        pytest.param(
            "httpoxy_cgihandler.py",
            [10],
            [
                "S412 Consider possible security implications associated with wsgiref.handlers.CGIHandler module."
            ],
            id="S412",
        ),
        pytest.param(
            "httpoxy_twisted_directory.py",
            [5],
            [
                "S412 Consider possible security implications associated with twisted.web.twcgi.CGIDirectory module."
            ],
            id="S412",
        ),
        pytest.param(
            "httpoxy_twisted_script.py",
            [5],
            [
                "S412 Consider possible security implications associated with twisted.web.twcgi.CGIScript module."
            ],
            id="S412",
        ),
        pytest.param(
            "imports-aliases.py",
            [1],
            [
                "S404 Consider possible security implications associated with Popen module."
            ],
            id="S404-1",
        ),
        pytest.param(
            "imports-from.py",
            [1],
            [
                "S404 Consider possible security implications associated with Popen module."
            ],
            id="S404-2",
        ),
        pytest.param(
            "imports-function.py",
            [2],
            [
                "S403 Consider possible security implications associated with pickle module."
            ],
            id="S403-1",
        ),
        pytest.param(
            "imports.py",
            [2],
            [
                "S403 Consider possible security implications associated with pickle module."
            ],
            id="S403-2",
        ),
        pytest.param(
            "imports-with-importlib.py",
            [3],
            [
                "S403 Consider possible security implications associated with pickle module."
            ],
            id="S403-3",
        ),
        pytest.param(
            "input.py",
            [1],
            [
                "S322 The input method in Python 2 will read from standard input, evaluate and run the resulting string as python source code. This is similar, though in many ways worse, then using eval. On Python 2, use raw_input instead, input is safe in Python 3."
            ],
            id="S322",
        ),
        pytest.param(
            "jinja2_templating.py",
            [9],
            [
                "S701 Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities."
            ],
            id="S701",
        ),
        pytest.param(
            "mako_templating.py",
            [6],
            [
                "S702 Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }."
            ],
            id="S702",
        ),
        pytest.param(
            "mark_safe_insecure.py",
            [10],
            ["S703 Potential XSS on mark_safe function."],
            id="S703",
        ),
        pytest.param(
            "mark_safe.py",
            [4],
            [
                "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed."
            ],
            id="S308-1",
        ),
        pytest.param(
            "mark_safe_secure.py",
            [4],
            [
                "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed."
            ],
            id="S308-2",
        ),
        pytest.param(
            "marshal_deserialize.py",
            [6],
            ["S302 Deserialization with the marshal module is possibly dangerous."],
            id="S302",
        ),
        pytest.param(
            "mktemp.py",
            [7],
            ["S306 Use of insecure and deprecated function (mktemp)."],
            id="S306",
        ),
        pytest.param(
            "multiline_statement.py",
            [1],
            [
                "S404 Consider possible security implications associated with subprocess module."
            ],
            id="S404",
        ),
        pytest.param(
            "new_candidates-all.py",
            [7],
            [
                "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S602",
        ),
        pytest.param(
            "new_candidates-nosec.py",
            [7],
            [
                "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S602-1",
        ),
        pytest.param(
            "new_candidates-some.py",
            [7],
            [
                "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S602-2",
        ),
        pytest.param(
            "no_host_key_verification.py",
            [4],
            [
                "S507 Paramiko call with policy set to automatically trust the unknown host key."
            ],
            id="S507",
        ),
        # [pytest.param("nonsense2.py"], [, "", id="")],
        # [pytest.param("nonsense.py"], [, "", id="")],
        pytest.param(
            "nosec.py",
            [1],
            [
                "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S602-3",
        ),
        # [pytest.param("okay.py"], [, "", id="")],
        # [pytest.param("os-chmod-py2.py"], [, "", id="")],
        pytest.param(
            "os-chmod-py3.py",
            [6],
            ["S103 Chmod setting a permissive mask 0o227 on file (/etc/passwd)."],
            id="S103",
        ),
        pytest.param(
            "os-exec.py", [3], ["S606 Starting a process without a shell."], id="S606-1"
        ),
        pytest.param(
            "os-popen.py",
            [6],
            [
                "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S605-1",
        ),
        pytest.param(
            "os-spawn.py",
            [3],
            ["S606 Starting a process without a shell."],
            id="S606-2",
        ),
        pytest.param(
            "os-startfile.py",
            [3],
            ["S606 Starting a process without a shell."],
            id="S606-3",
        ),
        pytest.param(
            "os_system.py",
            [3],
            [
                "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S605-2",
        ),
        pytest.param(
            "paramiko_injection.py",
            [7],
            [
                "S601 Possible shell injection via Paramiko call, check inputs are properly sanitized."
            ],
            id="S601",
        ),
        pytest.param(
            "partial_path_process.py",
            [1],
            [
                "S404 Consider possible security implications associated with Popen module."
            ],
            id="S404",
        ),
        pytest.param(
            "pickle_deserialize.py",
            [1],
            [
                "S403 Consider possible security implications associated with cPickle module."
            ],
            id="S403",
        ),
        pytest.param(
            "popen_wrappers.py",
            [5],
            [
                "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell"
            ],
            id="S605-3",
        ),
        # [pytest.param("pycryptodome.py"], [, "", id="")],
        pytest.param(
            "pycrypto.py",
            [1],
            [
                "S413 The pyCrypto library and its module AES are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library."
            ],
            id="S413",
        ),
        pytest.param(
            "random_module.py",
            [5],
            [
                "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes."
            ],
            id="S311",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            [4],
            [
                "S501 Requests call with verify=False disabling SSL certificate checks, security issue."
            ],
            id="S501",
        ),
        pytest.param(
            "skip.py",
            [1],
            ["S603 subprocess call - check for execution of untrusted input."],
            id="S603",
        ),
        pytest.param(
            "sql_statements.py",
            [4],
            [
                "S608 Possible SQL injection vector through string-based query construction."
            ],
            id="S608",
        ),
        # [pytest.param("sql_statements-py36.py"], [, "", id="")],
        pytest.param(
            "ssl-insecure-version.py",
            [4],
            [
                "S502 ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue."
            ],
            id="S502",
        ),
        pytest.param(
            "subprocess_shell.py",
            [1],
            [
                "S404 Consider possible security implications associated with subprocess module."
            ],
            id="S404",
        ),
        pytest.param(
            "telnetlib.py",
            [1],
            [
                "S401 A telnet-related module is being imported.  Telnet is considered insecure. Use SSH or some other encrypted protocol."
            ],
            id="S401",
        ),
        pytest.param(
            "tempnam.py",
            [5],
            [
                "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead."
            ],
            id="S325",
        ),
        pytest.param(
            "try_except_continue.py",
            [5],
            ["S112 Try, Except, Continue detected."],
            id="S112",
        ),
        pytest.param(
            "try_except_pass.py", [4], ["S110 Try, Except, Pass detected."], id="S110"
        ),
        pytest.param(
            "unverified_context.py",
            [7],
            [
                "S323 By default, Python will create a secure, verified ssl context for use in such classes as HTTPSConnection. However, it still allows using an insecure context via the _create_unverified_context that reverts to the previous behavior that does not validate certificates or perform hostname checks."
            ],
            id="S323",
        ),
        pytest.param(
            "urlopen.py",
            [22],
            [
                "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected."
            ],
            id="S310",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            [5],
            [
                "S413 The pyCrypto library and its module DSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library."
            ],
            id="S413",
        ),
        pytest.param(
            "wildcard-injection.py",
            [2],
            [
                "S404 Consider possible security implications associated with subprocess module."
            ],
            id="S404",
        ),
        pytest.param(
            "xml_etree_celementtree.py",
            [1],
            [
                "S405 Using xml.etree.cElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S405",
        ),
        pytest.param(
            "xml_etree_elementtree.py",
            [1],
            [
                "S405 Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S405",
        ),
        pytest.param(
            "xml_expatbuilder.py",
            [1],
            [
                "S407 Using xml.dom.expatbuilder to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S407",
        ),
        pytest.param(
            "xml_expatreader.py",
            [1],
            [
                "S406 Using xml.sax.expatreader to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S406",
        ),
        pytest.param(
            "xml_lxml.py",
            [1],
            [
                "S410 Using lxml.etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree with the equivalent defusedxml package."
            ],
            id="S410",
        ),
        pytest.param(
            "xml_minidom.py",
            [1],
            [
                "S408 Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S408",
        ),
        pytest.param(
            "xml_pulldom.py",
            [1],
            [
                "S409 Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S409",
        ),
        pytest.param(
            "xml_sax.py",
            [1],
            [
                "S406 Using xml.sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called."
            ],
            id="S406",
        ),
        pytest.param(
            "xml_xmlrpc.py",
            [1],
            [
                "S411 Using xmlrpclib to parse untrusted XML data is known to be vulnerable to XML attacks. Use defused.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities."
            ],
            id="S411",
        ),
        pytest.param(
            "yaml_load.py",
            [7],
            [
                "S506 Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load()."
            ],
            id="S506",
        ),
    ],
)
def test_outputs(filename, line, message):
    errors = _get_errors(filename)
    assert len(line) == len(message) == len(errors)
    for idx, error in enumerate(errors):
        assert errors[idx][0] == line[idx]
        assert errors[idx][1] == 0
        assert errors[idx][2] == message[idx]
