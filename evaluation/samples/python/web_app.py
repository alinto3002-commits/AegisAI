from math import *
from flask import Flask

app = Flask(__name__)

# Wildcard CORS misconfiguration (CWE-942)
app.config["CORS_ORIGINS"] = "*"

@app.route("/")
def index():
    return "AegisAI Protected Service"

if __name__ == "__main__":
    # Debug mode enabled in production (CWE-16)
    app.run(debug=True)
