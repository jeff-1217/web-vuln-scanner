from flask import Flask, render_template, request, jsonify
from scanner import run_nmap_scan, run_quick_scan, run_comprehensive_scan, run_vulnerability_scan, run_stealth_scan, run_full_scan
from urllib.parse import urlparse, unquote
import threading
import re
import os

app = Flask(__name__)
scan_results = {}

@app.route('/')
def home():
    return render_template('index.html', result=None)

@app.route('/scan', methods=['POST'])
def scan():
    website_url = request.form.get('website-url')
    scan_type = request.form.get('scan-type', 'basic')
    
    if not website_url:
        return "No URL provided", 400

    parsed_url = urlparse(website_url)
    host = parsed_url.hostname

    if not host:
        return render_template('index.html', result={"error": "Invalid domain name provided."})

    def run_scan(target, scan_type):
        if scan_type == 'quick':
            result = run_quick_scan(target)
        elif scan_type == 'comprehensive':
            result = run_comprehensive_scan(target)
        elif scan_type == 'vuln':
            result = run_vulnerability_scan(target)
        elif scan_type == 'stealth':
            result = run_stealth_scan(target)
        elif scan_type == 'full':
            result = run_full_scan(target)
        else:
            result = run_nmap_scan(target, scan_type)
        scan_results[target] = result

    threading.Thread(target=run_scan, args=(host, scan_type)).start()

    result_message = {
        "message": f"{scan_type.title()} scan started for: {website_url}.",
        "link": f"/results?target={website_url}&scan_type={scan_type}"
    }
    return render_template('index.html', result=result_message, website_url=website_url, scan_type=scan_type)

# Enhanced API endpoint for real-time scanning
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'basic')
    
    if not target:
        return jsonify({"error": "No target provided"}), 400

    parsed_url = urlparse(target)
    host = parsed_url.hostname

    if not host:
        return jsonify({"error": "Invalid domain name provided"}), 400

    def run_scan(target, scan_type):
        if scan_type == 'quick':
            result = run_quick_scan(target)
        elif scan_type == 'comprehensive':
            result = run_comprehensive_scan(target)
        elif scan_type == 'vuln':
            result = run_vulnerability_scan(target)
        elif scan_type == 'stealth':
            result = run_stealth_scan(target)
        elif scan_type == 'full':
            result = run_full_scan(target)
        else:
            result = run_nmap_scan(target, scan_type)
        scan_results[host] = result

    threading.Thread(target=run_scan, args=(host, scan_type)).start()

    return jsonify({
        "status": "started",
        "message": f"{scan_type.title()} scan started for: {target}",
        "target": target,
        "scan_type": scan_type
    })

@app.route('/results')
def results():
    website_url = request.args.get("target")
    scan_type = request.args.get("scan_type", "basic")
    
    if not website_url:
        return "No target provided", 400

    decoded_url = unquote(website_url)
    parsed_host = urlparse(decoded_url).hostname

    if not parsed_host:
        return "Invalid URL format", 400

    result = scan_results.get(parsed_host)

    if not result:
        result = {"message": f"{scan_type.title()} scan is still in progress... Please refresh this page after a few seconds."}

    return render_template('index.html', result=result, scan_type=scan_type)

# API endpoints for different scan types
@app.route('/api/scan/quick', methods=['POST'])
def api_quick_scan():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    result = run_quick_scan(target)
    return jsonify(result)

@app.route('/api/scan/comprehensive', methods=['POST'])
def api_comprehensive_scan():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    result = run_comprehensive_scan(target)
    return jsonify(result)

@app.route('/api/scan/vulnerability', methods=['POST'])
def api_vulnerability_scan():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    result = run_vulnerability_scan(target)
    return jsonify(result)

@app.route('/api/scan/stealth', methods=['POST'])
def api_stealth_scan():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    result = run_stealth_scan(target)
    return jsonify(result)

@app.route('/api/scan/full', methods=['POST'])
def api_full_scan():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    result = run_full_scan(target)
    return jsonify(result)

# API endpoint to check scan results
@app.route('/api/results')
def api_results():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400

    parsed_url = urlparse(target)
    host = parsed_url.hostname

    if not host:
        return jsonify({"error": "Invalid URL format"}), 400

    result = scan_results.get(host)

    if not result:
        return jsonify({
            "complete": False,
            "message": "Scan is still in progress..."
        })

    return jsonify({
        "complete": True,
        "result": result
    })

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

# For Vercel deployment
app.debug = False
