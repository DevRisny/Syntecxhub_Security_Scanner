"""A tiny intentionally-misconfigured Flask site, for trying the scanner against a target
you own. Not meant to be exposed on a real network — bind to localhost only.

    pip install flask
    python examples/demo_site.py
    secscan http://127.0.0.1:8090 --html report.html
"""

from flask import Flask, make_response

app = Flask(__name__)


@app.route("/")
def home():
    resp = make_response(
        "<html><head><title>Demo</title></head><body>"
        "<h1>Demo site</h1><a href='/about'>About</a> | <a href='/error'>Trigger error</a>"
        "</body></html>"
    )
    # Deliberately missing security headers, insecure cookie: this is the "vulnerable" target.
    resp.set_cookie("session", "demo-value")
    resp.headers["Server"] = "Werkzeug/3.0.1 Python/3.11.4"
    return resp


@app.route("/about")
def about():
    return "<html><body>About this demo.</body></html>"


@app.route("/error")
def error():
    # Simulates an app that leaks a stack trace to the client.
    return (
        "Traceback (most recent call last):\n"
        '  File "app.py", line 42, in handler\n'
        "    1 / 0\n"
        "ZeroDivisionError: division by zero",
        500,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8090)
