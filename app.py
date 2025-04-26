from flask import Flask, render_template, request
from scanner import run_nmap_scan
from urllib.parse import urlparse, unquote
import threading
import re

app = Flask(__name__)
scan_results = {}

@app.route('/')
def home():
    return render_template('index.html', result=None)

@app.route('/scan', methods=['POST'])
def scan():
    website_url = request.form.get('website-url')
    if not website_url:
        return "No URL provided", 400

    parsed_url = urlparse(website_url)
    host = parsed_url.hostname

    if not host or not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return render_template('index.html', result={"error": "Invalid domain name provided."})

    def run_scan(target):
        result = run_nmap_scan(target)
        scan_results[target] = result

    threading.Thread(target=run_scan, args=(host,)).start()

    result_message = {
        "message": f"Scan started for: {website_url}.",
        "link": f"/results?target={website_url}"
    }
    return render_template('index.html', result=result_message, website_url=website_url)

@app.route('/results')
def results():
    website_url = request.args.get("target")
    if not website_url:
        return "No target provided", 400

    decoded_url = unquote(website_url)
    parsed_host = urlparse(decoded_url).hostname

    if not parsed_host:
        return "Invalid URL format", 400

    result = scan_results.get(parsed_host)

    if not result:
        result = {"message": "Scan is still in progress... Please refresh this page after a few seconds."}

    return render_template('index.html', result=result)
    if __name__ == "__main__":
        import os
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port)
