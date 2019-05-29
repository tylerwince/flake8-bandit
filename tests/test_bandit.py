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
            1,
            "S101 Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
        ),
        pytest.param("binding.py", 4, "S104 Possible binding to all interfaces."),
        pytest.param(
            "cipher-modes.py",
            6,
            "S305 Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB.",
        ),
        pytest.param(
            "ciphers.py",
            1,
            "S413 The pyCrypto library and its module ARC2 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            2,
            "S413 The pyCrypto library and its module ARC4 are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            3,
            "S413 The pyCrypto library and its module Blowfish are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            4,
            "S413 The pyCrypto library and its module DES are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            5,
            "S413 The pyCrypto library and its module XOR are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            11,
            "S413 The pyCrypto library and its module SHA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            12,
            "S413 The pyCrypto library and its module Random are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            13,
            "S413 The pyCrypto library and its module Counter are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "ciphers.py",
            22,
            "S304 Use of insecure cipher Crypto.Cipher.ARC2.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            24,
            "S304 Use of insecure cipher Cryptodome.Cipher.ARC2.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            29,
            "S303 Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
        ),
        pytest.param(
            "ciphers.py",
            30,
            "S304 Use of insecure cipher Crypto.Cipher.ARC4.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            32,
            "S304 Use of insecure cipher Cryptodome.Cipher.ARC4.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            42,
            "S304 Use of insecure cipher Crypto.Cipher.Blowfish.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            45,
            "S304 Use of insecure cipher Cryptodome.Cipher.Blowfish.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            52,
            "S304 Use of insecure cipher Crypto.Cipher.DES.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            56,
            "S304 Use of insecure cipher Cryptodome.Cipher.DES.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            61,
            "S304 Use of insecure cipher Crypto.Cipher.XOR.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            63,
            "S304 Use of insecure cipher Cryptodome.Cipher.XOR.new. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            66,
            "S304 Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.ARC4. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            70,
            "S304 Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.Blowfish. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "ciphers.py",
            74,
            "S304 Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.IDEA. Replace with a known secure cipher such as AES.",
        ),
        pytest.param(
            "dill.py",
            1,
            "S403 Consider possible security implications associated with dill module.",
        ),
        pytest.param(
            "dill.py",
            6,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "dill.py",
            11,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            12,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            13,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            15,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            16,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            17,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            20,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            22,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            23,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            24,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            27,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_extra.py",
            29,
            "S610 Use of extra potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_raw.py",
            5,
            "S611 Use of RawSQL potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_raw.py",
            6,
            "S611 Use of RawSQL potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_raw.py",
            8,
            "S611 Use of RawSQL potential SQL attack vector.",
        ),
        pytest.param(
            "django_sql_injection_raw.py",
            11,
            "S611 Use of RawSQL potential SQL attack vector.",
        ),
        pytest.param(
            "eval.py",
            3,
            "S307 Use of possibly insecure function - consider using safer ast.literal_eval.",
        ),
        pytest.param(
            "eval.py",
            4,
            "S307 Use of possibly insecure function - consider using safer ast.literal_eval.",
        ),
        pytest.param(
            "eval.py",
            5,
            "S307 Use of possibly insecure function - consider using safer ast.literal_eval.",
        ),
        pytest.param("exec-py3.py", 1, "S102 Use of exec detected."),
        pytest.param(
            "flask_debug.py",
            10,
            "S201 A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
        ),
        pytest.param(
            "ftplib.py",
            1,
            "S402 A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
        ),
        pytest.param(
            "ftplib.py",
            3,
            "S321 FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
        ),
        pytest.param(
            "hardcoded-passwords.py", 1, "S107 Possible hardcoded password: 'Admin'"
        ),
        pytest.param(
            "hardcoded-passwords.py", 5, "S105 Possible hardcoded password: 'root'"
        ),
        pytest.param(
            "hardcoded-passwords.py", 9, "S105 Possible hardcoded password: ''"
        ),
        pytest.param(
            "hardcoded-passwords.py",
            13,
            "S105 Possible hardcoded password: 'ajklawejrkl42348swfgkg'",
        ),
        pytest.param(
            "hardcoded-passwords.py", 16, "S107 Possible hardcoded password: 'blerg'"
        ),
        pytest.param(
            "hardcoded-passwords.py", 22, "S106 Possible hardcoded password: 'blerg'"
        ),
        pytest.param(
            "hardcoded-passwords.py", 23, "S105 Possible hardcoded password: 'blerg'"
        ),
        pytest.param(
            "hardcoded-passwords.py", 24, "S105 Possible hardcoded password: 'blerg'"
        ),
        pytest.param(
            "hardcoded-passwords.py", 26, "S105 Possible hardcoded password: 'secret'"
        ),
        pytest.param(
            "hardcoded-passwords.py",
            27,
            "S105 Possible hardcoded password: 'emails_secret'",
        ),
        pytest.param(
            "hardcoded-passwords.py",
            28,
            "S105 Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'",
        ),
        pytest.param(
            "hardcoded-passwords.py", 29, "S105 Possible hardcoded password: '1234'"
        ),
        pytest.param(
            "hardcoded-tmp.py",
            1,
            "S108 Probable insecure usage of temp file/directory.",
        ),
        pytest.param(
            "hardcoded-tmp.py",
            8,
            "S108 Probable insecure usage of temp file/directory.",
        ),
        pytest.param(
            "hardcoded-tmp.py",
            11,
            "S108 Probable insecure usage of temp file/directory.",
        ),
        pytest.param(
            "hashlib_new_insecure_functions.py",
            3,
            "S324 Use of insecure MD4 or MD5 hash function.",
        ),
        pytest.param(
            "hashlib_new_insecure_functions.py",
            5,
            "S324 Use of insecure MD4 or MD5 hash function.",
        ),
        pytest.param(
            "hashlib_new_insecure_functions.py",
            7,
            "S324 Use of insecure MD4 or MD5 hash function.",
        ),
        pytest.param(
            "hashlib_new_insecure_functions.py",
            9,
            "S324 Use of insecure MD4 or MD5 hash function.",
        ),
        pytest.param(
            "hashlib_new_insecure_functions.py",
            11,
            "S324 Use of insecure MD4 or MD5 hash function.",
        ),
        pytest.param(
            "httplib_https.py",
            2,
            "S309 Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033",
        ),
        pytest.param(
            "httplib_https.py",
            5,
            "S309 Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033",
        ),
        pytest.param(
            "httplib_https.py",
            8,
            "S309 Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033",
        ),
        pytest.param(
            "httpoxy_cgihandler.py",
            10,
            "S412 Consider possible security implications associated with wsgiref.handlers.CGIHandler module.",
        ),
        pytest.param(
            "httpoxy_twisted_directory.py",
            5,
            "S412 Consider possible security implications associated with twisted.web.twcgi.CGIDirectory module.",
        ),
        pytest.param(
            "httpoxy_twisted_script.py",
            5,
            "S412 Consider possible security implications associated with twisted.web.twcgi.CGIScript module.",
        ),
        pytest.param(
            "imports-aliases.py",
            1,
            "S404 Consider possible security implications associated with Popen module.",
        ),
        pytest.param(
            "imports-aliases.py",
            6,
            "S403 Consider possible security implications associated with loads module.",
        ),
        pytest.param(
            "imports-aliases.py",
            7,
            "S403 Consider possible security implications associated with pickle module.",
        ),
        pytest.param(
            "imports-aliases.py",
            9,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "imports-aliases.py",
            11,
            "S303 Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
        ),
        pytest.param(
            "imports-aliases.py",
            12,
            "S303 Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
        ),
        pytest.param(
            "imports-aliases.py",
            13,
            "S303 Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
        ),
        pytest.param(
            "imports-aliases.py",
            14,
            "S303 Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
        ),
        pytest.param(
            "imports-aliases.py",
            15,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "imports-from.py",
            1,
            "S404 Consider possible security implications associated with Popen module.",
        ),
        pytest.param(
            "imports-from.py",
            6,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "imports-from.py",
            7,
            "S404 Consider possible security implications associated with Popen module.",
        ),
        pytest.param(
            "imports-function.py",
            2,
            "S403 Consider possible security implications associated with pickle module.",
        ),
        pytest.param(
            "imports-function.py",
            4,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "imports.py",
            2,
            "S403 Consider possible security implications associated with pickle module.",
        ),
        pytest.param(
            "imports.py",
            4,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "imports-with-importlib.py",
            3,
            "S403 Consider possible security implications associated with pickle module.",
        ),
        pytest.param(
            "imports-with-importlib.py",
            5,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "input.py",
            1,
            "S322 The input method in Python 2 will read from standard input, evaluate and run the resulting string as python source code. This is similar, though in many ways worse, then using eval. On Python 2, use raw_input instead, input is safe in Python 3.",
        ),
        pytest.param(
            "jinja2_templating.py",
            9,
            "S701 Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.",
        ),
        pytest.param(
            "jinja2_templating.py",
            10,
            "S701 Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Use autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.",
        ),
        pytest.param(
            "jinja2_templating.py",
            11,
            "S701 Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Use autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.",
        ),
        pytest.param(
            "jinja2_templating.py",
            15,
            "S701 By default, jinja2 sets autoescape to False. Consider using autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.",
        ),
        pytest.param(
            "jinja2_templating.py",
            26,
            "S701 Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.",
        ),
        pytest.param(
            "mako_templating.py",
            6,
            "S702 Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.",
        ),
        pytest.param(
            "mako_templating.py",
            10,
            "S702 Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.",
        ),
        pytest.param(
            "mako_templating.py",
            11,
            "S702 Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 10, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            10,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 11, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py", 12, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py", 13, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py", 14, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py", 22, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            22,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 30, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            30,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py",
            35,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 41, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            41,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py",
            46,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 54, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            54,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 59, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            59,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 64, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            64,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 69, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            69,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 74, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            74,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 79, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            79,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 84, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            84,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 89, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            89,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 94, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            94,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 99, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            99,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 104, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            104,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 109, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            109,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 114, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            114,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 119, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            119,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py",
            124,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 126, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            126,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 133, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            133,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 143, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            143,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 149, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            149,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 153, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            153,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_insecure.py", 159, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_insecure.py",
            159,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe.py",
            4,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            4,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            11,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            14,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            17,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            29,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            33,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            35,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            36,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            37,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py", 38, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_secure.py",
            38,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py", 39, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_secure.py",
            39,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            41,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            45,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            47,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            48,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py", 49, "S703 Potential XSS on mark_safe function."
        ),
        pytest.param(
            "mark_safe_secure.py",
            49,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            54,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            62,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            65,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "mark_safe_secure.py",
            75,
            "S308 Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
        ),
        pytest.param(
            "marshal_deserialize.py",
            6,
            "S302 Deserialization with the marshal module is possibly dangerous.",
        ),
        pytest.param(
            "marshal_deserialize.py",
            11,
            "S302 Deserialization with the marshal module is possibly dangerous.",
        ),
        pytest.param(
            "mktemp.py", 7, "S306 Use of insecure and deprecated function (mktemp)."
        ),
        pytest.param(
            "mktemp.py", 8, "S306 Use of insecure and deprecated function (mktemp)."
        ),
        pytest.param(
            "mktemp.py", 9, "S306 Use of insecure and deprecated function (mktemp)."
        ),
        pytest.param(
            "mktemp.py", 10, "S306 Use of insecure and deprecated function (mktemp)."
        ),
        pytest.param(
            "multiline_statement.py",
            1,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "multiline_statement.py",
            5,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "new_candidates-all.py",
            7,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "new_candidates-all.py",
            9,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "new_candidates-all.py",
            15,
            "S506 Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
        ),
        pytest.param(
            "new_candidates-all.py",
            17,
            "S506 Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
        ),
        pytest.param(
            "new_candidates-all.py",
            22,
            "S317 Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "new_candidates-all.py",
            24,
            "S317 Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "new_candidates-nosec.py",
            7,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "new_candidates-nosec.py",
            13,
            "S506 Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
        ),
        pytest.param(
            "new_candidates-nosec.py",
            18,
            "S317 Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "new_candidates-some.py",
            7,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "new_candidates-some.py",
            9,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "new_candidates-some.py",
            15,
            "S506 Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
        ),
        pytest.param(
            "new_candidates-some.py",
            20,
            "S317 Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "no_host_key_verification.py",
            4,
            "S507 Paramiko call with policy set to automatically trust the unknown host key.",
        ),
        pytest.param(
            "no_host_key_verification.py",
            5,
            "S507 Paramiko call with policy set to automatically trust the unknown host key.",
        ),
        pytest.param(
            "os-chmod-py3.py",
            6,
            "S103 Chmod setting a permissive mask 0o227 on file (/etc/passwd).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            7,
            "S103 Chmod setting a permissive mask 0o7 on file (/etc/passwd).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            9,
            "S103 Chmod setting a permissive mask 0o777 on file (/etc/passwd).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            10,
            "S103 Chmod setting a permissive mask 0o770 on file (/etc/passwd).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            11,
            "S103 Chmod setting a permissive mask 0o776 on file (/etc/passwd).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            13,
            "S103 Chmod setting a permissive mask 0o777 on file (~/.bashrc).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            14,
            "S103 Chmod setting a permissive mask 0o777 on file (/etc/hosts).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            15,
            "S103 Chmod setting a permissive mask 0o777 on file (/tmp/oh_hai).",
        ),
        pytest.param(
            "os-chmod-py3.py",
            15,
            "S108 Probable insecure usage of temp file/directory.",
        ),
        pytest.param(
            "os-chmod-py3.py",
            17,
            "S103 Chmod setting a permissive mask 0o777 on file (key_file).",
        ),
        pytest.param("os-exec.py", 3, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 4, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 5, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 6, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 7, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 8, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 9, "S606 Starting a process without a shell."),
        pytest.param("os-exec.py", 10, "S606 Starting a process without a shell."),
        pytest.param(
            "os-popen.py",
            6,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            7,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            8,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            9,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            10,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            11,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            12,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            14,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "os-popen.py",
            15,
            "S605 Starting a process with a shell, possible injection detected, security issue.",
        ),
        pytest.param("os-spawn.py", 3, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 4, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 5, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 6, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 7, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 8, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 9, "S606 Starting a process without a shell."),
        pytest.param("os-spawn.py", 10, "S606 Starting a process without a shell."),
        pytest.param("os-startfile.py", 3, "S606 Starting a process without a shell."),
        pytest.param("os-startfile.py", 4, "S606 Starting a process without a shell."),
        pytest.param("os-startfile.py", 5, "S606 Starting a process without a shell."),
        pytest.param(
            "os_system.py",
            3,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "paramiko_injection.py",
            7,
            "S601 Possible shell injection via Paramiko call, check inputs are properly sanitized.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            1,
            "S403 Consider possible security implications associated with cPickle module.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            2,
            "S403 Consider possible security implications associated with pickle module.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            8,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            13,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            16,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            20,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            25,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "pickle_deserialize.py",
            28,
            "S301 Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.",
        ),
        pytest.param(
            "popen_wrappers.py",
            5,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "popen_wrappers.py",
            6,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "popen_wrappers.py",
            11,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "popen_wrappers.py",
            12,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "popen_wrappers.py",
            13,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "popen_wrappers.py",
            14,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "popen_wrappers.py",
            15,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "pycrypto.py",
            1,
            "S413 The pyCrypto library and its module AES are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "pycrypto.py",
            2,
            "S413 The pyCrypto library and its module Random are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "random_module.py",
            5,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "random_module.py",
            6,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "random_module.py",
            7,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "random_module.py",
            8,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "random_module.py",
            9,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "random_module.py",
            10,
            "S311 Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            4,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            6,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            8,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            10,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            12,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            14,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "requests-ssl-verify-disabled.py",
            16,
            "S501 Requests call with verify=False disabling SSL certificate checks, security issue.",
        ),
        pytest.param(
            "skip.py",
            1,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "skip.py",
            2,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "skip.py",
            3,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "skip.py",
            4,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "skip.py",
            5,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "skip.py",
            6,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "skip.py",
            7,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "sql_statements.py",
            4,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            5,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            6,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            7,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            9,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            11,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            12,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            15,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            16,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            17,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            18,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            20,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            21,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "sql_statements.py",
            35,
            "S608 Possible SQL injection vector through string-based query construction.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            4,
            "S502 ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            5,
            "S502 SSL.Context call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            6,
            "S502 SSL.Context call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            8,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            9,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            10,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            13,
            "S502 ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            14,
            "S502 ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            15,
            "S502 SSL.Context call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            16,
            "S502 SSL.Context call with insecure SSL/TLS protocol version identified, security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            18,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            19,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            20,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            21,
            "S502 Function call with insecure SSL/TLS protocol identified, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            23,
            "S504 ssl.wrap_socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            25,
            "S503 Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            28,
            "S503 Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.",
        ),
        pytest.param(
            "ssl-insecure-version.py",
            31,
            "S503 Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            1,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "subprocess_shell.py",
            2,
            "S404 Consider possible security implications associated with Popen module.",
        ),
        pytest.param(
            "subprocess_shell.py",
            11,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            12,
            "S604 Function call with shell=True parameter identified, possible security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            14,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            15,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            16,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            18,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            21,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            23,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            24,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            26,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            27,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            29,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            30,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            32,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            33,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            34,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            37,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            39,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "subprocess_shell.py",
            42,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            43,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            44,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            45,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            47,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            48,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            49,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            50,
            "S602 subprocess call with shell=True identified, security issue.",
        ),
        pytest.param(
            "subprocess_shell.py",
            52,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            53,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            54,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            55,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "subprocess_shell.py",
            56,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "telnetlib.py",
            1,
            "S401 A telnet-related module is being imported.  Telnet is considered insecure. Use SSH or some other encrypted protocol.",
        ),
        pytest.param(
            "telnetlib.py",
            8,
            "S312 Telnet-related functions are being called. Telnet is considered insecure. Use SSH or some other encrypted protocol.",
        ),
        pytest.param(
            "tempnam.py",
            5,
            "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        ),
        pytest.param(
            "tempnam.py",
            7,
            "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        ),
        pytest.param(
            "tempnam.py",
            9,
            "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        ),
        pytest.param(
            "tempnam.py",
            10,
            "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        ),
        pytest.param(
            "tempnam.py",
            12,
            "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        ),
        pytest.param(
            "tempnam.py",
            13,
            "S325 Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
        ),
        pytest.param(
            "try_except_continue.py", 5, "S112 Try, Except, Continue detected."
        ),
        pytest.param(
            "try_except_continue.py", 13, "S112 Try, Except, Continue detected."
        ),
        pytest.param("try_except_pass.py", 4, "S110 Try, Except, Pass detected."),
        pytest.param("try_except_pass.py", 11, "S110 Try, Except, Pass detected."),
        pytest.param(
            "unverified_context.py",
            7,
            "S323 By default, Python will create a secure, verified ssl context for use in such classes as HTTPSConnection. However, it still allows using an insecure context via the _create_unverified_context that reverts to the previous behavior that does not validate certificates or perform hostname checks.",
        ),
        pytest.param(
            "urlopen.py",
            22,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            23,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            24,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            27,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            38,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            39,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            42,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            43,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            44,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            47,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            52,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            53,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            54,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "urlopen.py",
            57,
            "S310 Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            5,
            "S413 The pyCrypto library and its module DSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            6,
            "S413 The pyCrypto library and its module RSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            38,
            "S505 DSA key sizes below 2048 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            40,
            "S505 EC key sizes below 224 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            42,
            "S505 RSA key sizes below 2048 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            45,
            "S505 DSA key sizes below 2048 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            46,
            "S505 RSA key sizes below 2048 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            47,
            "S505 DSA key sizes below 2048 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            48,
            "S505 RSA key sizes below 2048 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            51,
            "S505 DSA key sizes below 1024 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            53,
            "S505 EC key sizes below 224 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            55,
            "S505 RSA key sizes below 1024 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            58,
            "S505 DSA key sizes below 1024 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            59,
            "S505 RSA key sizes below 1024 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            60,
            "S505 DSA key sizes below 1024 bits are considered breakable. ",
        ),
        pytest.param(
            "weak_cryptographic_key_sizes.py",
            61,
            "S505 RSA key sizes below 1024 bits are considered breakable. ",
        ),
        pytest.param(
            "wildcard-injection.py",
            2,
            "S404 Consider possible security implications associated with subprocess module.",
        ),
        pytest.param(
            "wildcard-injection.py",
            5,
            "S609 Possible wildcard injection in call: os.system",
        ),
        pytest.param(
            "wildcard-injection.py",
            5,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "wildcard-injection.py",
            6,
            "S609 Possible wildcard injection in call: os.system",
        ),
        pytest.param(
            "wildcard-injection.py",
            6,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "wildcard-injection.py",
            7,
            "S609 Possible wildcard injection in call: os.popen2",
        ),
        pytest.param(
            "wildcard-injection.py",
            7,
            "S605 Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "wildcard-injection.py",
            8,
            "S609 Possible wildcard injection in call: subprocess.Popen",
        ),
        pytest.param(
            "wildcard-injection.py",
            8,
            "S602 subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
        ),
        pytest.param(
            "wildcard-injection.py",
            11,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "wildcard-injection.py",
            12,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "wildcard-injection.py",
            13,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "wildcard-injection.py",
            14,
            "S603 subprocess call - check for execution of untrusted input.",
        ),
        pytest.param(
            "wildcard-injection.py", 16, "S606 Starting a process without a shell."
        ),
        pytest.param(
            "xml_etree_celementtree.py",
            1,
            "S405 Using xml.etree.cElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_etree_celementtree.py",
            7,
            "S313 Using xml.etree.cElementTree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.fromstring with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_celementtree.py",
            9,
            "S313 Using xml.etree.cElementTree.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_celementtree.py",
            10,
            "S313 Using xml.etree.cElementTree.iterparse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.iterparse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_celementtree.py",
            11,
            "S313 Using xml.etree.cElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_elementtree.py",
            1,
            "S405 Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_etree_elementtree.py",
            7,
            "S314 Using xml.etree.ElementTree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.fromstring with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_elementtree.py",
            9,
            "S314 Using xml.etree.ElementTree.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_elementtree.py",
            10,
            "S314 Using xml.etree.ElementTree.iterparse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.iterparse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_etree_elementtree.py",
            11,
            "S314 Using xml.etree.ElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_expatbuilder.py",
            1,
            "S407 Using xml.dom.expatbuilder to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_expatbuilder.py",
            4,
            "S316 Using xml.dom.expatbuilder.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_expatbuilder.py",
            9,
            "S316 Using xml.dom.expatbuilder.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_expatreader.py",
            1,
            "S406 Using xml.sax.expatreader to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_expatreader.py",
            4,
            "S315 Using xml.sax.expatreader.create_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader.create_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_lxml.py",
            1,
            "S410 Using lxml.etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree with the equivalent defusedxml package.",
        ),
        pytest.param(
            "xml_lxml.py",
            2,
            "S410 Using lxml to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml with the equivalent defusedxml package.",
        ),
        pytest.param(
            "xml_lxml.py",
            3,
            "S410 Using etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace etree with the equivalent defusedxml package.",
        ),
        pytest.param(
            "xml_lxml.py",
            8,
            "S320 Using lxml.etree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree.fromstring with its defusedxml equivalent function.",
        ),
        pytest.param(
            "xml_minidom.py",
            1,
            "S408 Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_minidom.py",
            3,
            "S318 Using xml.dom.minidom.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_minidom.py",
            9,
            "S408 Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_minidom.py",
            11,
            "S318 Using xml.dom.minidom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_pulldom.py",
            1,
            "S409 Using parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parseString with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_pulldom.py",
            3,
            "S319 Using xml.dom.pulldom.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.pulldom.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_pulldom.py",
            9,
            "S409 Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_pulldom.py",
            11,
            "S319 Using xml.dom.pulldom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.pulldom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_sax.py",
            1,
            "S406 Using xml.sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_sax.py",
            2,
            "S406 Using sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace sax with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
        ),
        pytest.param(
            "xml_sax.py",
            21,
            "S317 Using xml.sax.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_sax.py",
            22,
            "S317 Using xml.sax.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_sax.py",
            23,
            "S317 Using xml.sax.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_sax.py",
            24,
            "S317 Using xml.sax.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_sax.py",
            30,
            "S317 Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_sax.py",
            31,
            "S317 Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
        ),
        pytest.param(
            "xml_xmlrpc.py",
            1,
            "S411 Using xmlrpclib to parse untrusted XML data is known to be vulnerable to XML attacks. Use defused.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.",
        ),
        pytest.param(
            "yaml_load.py",
            7,
            "S506 Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
        ),
    ],
)
def test_outputs(filename, line, message):
    errors = _get_errors(filename)
    idxes = []
    for idx, error in enumerate(errors):
        # Some lines have multiple errors and
        # we need to check both
        if error[0] == line:
            idxes.append(idx)
    # Assume failing tests for multiple lines
    _pass = False
    for idx in idxes:
        if errors[idx][2] != message:
            continue
        # We found a matching message in the
        # index list
        _pass = True
        assert errors[idx][0] == line
        assert errors[idx][1] == 0
        assert errors[idx][2] == message
    if not _pass:
        print(errors[idx])
        print(idxes)
    assert _pass
