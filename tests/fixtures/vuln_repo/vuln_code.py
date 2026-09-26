"""Intentionally vulnerable fixture for T1a bandit/semgrep tests."""
import pickle
import subprocess

import yaml  # noqa: F401


def run_cmd(user_input):
    subprocess.call("ls " + user_input, shell=True)  # B602


def load_blob(blob):
    return pickle.loads(blob)  # B301


def dynamic(code):
    return eval(code)  # B307 / semgrep


def query(name):
    return "SELECT * FROM users WHERE name = '%s'" % name  # B608
