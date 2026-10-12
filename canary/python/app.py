"""DELIBERATELY VULNERABLE — scanner canary, never deploy.

.github/workflows/scanner-canary.yml runs the SAST workflow over this file and
asserts it reports findings. If it ever reports zero, a scanner has silently
stopped working (as Semgrep did with `--config=auto --metrics=off`).
"""
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/x")
def x():
    subprocess.call(request.args["c"], shell=True)
    conn = sqlite3.connect("a")
    conn.execute("SELECT * FROM t WHERE id=" + request.args["id"])
    return pickle.loads(request.data)
