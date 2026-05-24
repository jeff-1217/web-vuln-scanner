import streamlit as st
import os
import re
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

st.set_page_config(page_title="SOC Threat Agent", layout="wide")

# Custom CSS for the cards and UI elements
st.markdown("""
<style>
.metric-card {
    background: rgba(30, 30, 46, 0.7);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 20px;
    border-radius: 10px;
    border-left: 5px solid #00E676;
    margin-bottom: 20px;
    color: white;
}
.metric-card.malicious {
    border-left: 5px solid #FF5252;
}
.metric-card h3 { margin-top: 0; color: #E0E0E0; }
.metric-row { display: flex; justify-content: space-between; margin-bottom: 8px; }
.metric-label { color: #A0A0A0; font-weight: bold; width: 30%; }
.metric-value { color: #FFFFFF; width: 70%; }

.tip-card {
    background: rgba(255, 255, 255, 0.02);
    border: 1px dashed rgba(255, 255, 255, 0.1);
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 15px;
    color: #E0E0E0;
    font-size: 0.95rem;
}

/* Style all buttons */
.stButton>button {
    border-radius: 8px !important;
    transition: all 0.2s ease-in-out !important;
}
/* Primary button (Analyze Logs) */
.stButton>button[kind="primary"] {
    background: linear-gradient(135deg, #00F2FE 0%, #4FACFE 100%) !important;
    color: #0F0F1A !important;
    border: none !important;
    font-weight: bold !important;
    box-shadow: 0 4px 15px rgba(79, 172, 254, 0.3) !important;
}
.stButton>button[kind="primary"]:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 20px rgba(79, 172, 254, 0.5) !important;
}
/* Secondary buttons (Load Demo, Clear Log) */
.stButton>button[kind="secondary"] {
    background: rgba(255, 255, 255, 0.05) !important;
    color: #E0E0E0 !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
}
.stButton>button[kind="secondary"]:hover {
    background: rgba(255, 255, 255, 0.1) !important;
    color: #FFFFFF !important;
    border-color: rgba(255, 255, 255, 0.3) !important;
    transform: translateY(-1px) !important;
}
</style>
""", unsafe_allow_html=True)

st.title("SOC Threat Detection Agent")
st.markdown("This tool analyzes firewall logs in real-time, queries threat intelligence databases (AbuseIPDB, VirusTotal), and uses the **Groq Llama-3.3-70b** model to summarize findings and recommend actions.")

# Demo section
st.markdown("""
<div class="tip-card">
    💡 <b>Tip:</b> Don't have a log handy? Click <b>Load Demo Log</b> to insert a sample log with a known malicious IP (<code>174.138.38.186</code> - flagged by AbuseIPDB) to test the threat detection flow.
</div>
""", unsafe_allow_html=True)

# Initialize session state for log input if not already present
if "log_data" not in st.session_state:
    st.session_state.log_data = ""

def load_demo():
    st.session_state.log_data = "May 24 15:12:45 gateway-firewall: Connection from 174.138.38.186 rejected on port 22 (SSH)"

def clear_log():
    st.session_state.log_data = ""

col1, col2, _ = st.columns([2, 2, 8])
with col1:
    st.button("Load Demo Log ", on_click=load_demo, use_container_width=True)
with col2:
    st.button("Clear Log ", on_click=clear_log, use_container_width=True)

# Log input
log_input = st.text_area(
    "Paste your firewall logs here:",
    key="log_data",
    height=200,
    placeholder="Jan 01 12:35:25 firewall: HTTP connection from 45.33.32.156 accepted..."
)

def extract_ips(log_data: str) -> list:
    return list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_data)))

def check_abuseipdb(ip: str):
    if not ABUSEIPDB_API_KEY: return "API Key Missing", 0
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    try:
        response = requests.get(url, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': 30}, timeout=5)
        if response.status_code == 200:
            score = response.json()["data"]["abuseConfidenceScore"]
            return f"Malicious (Score: {score})" if score > 50 else f"Clean (Score: {score})", score
        return f"Error HTTP {response.status_code}", 0
    except Exception as e:
        return f"Error: {str(e)}", 0

def check_virustotal(ip: str):
    if not VIRUSTOTAL_API_KEY: return "API Key Missing", 0
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            if malicious > 0: return f"Malicious: {malicious}/{total} vendors flagged", malicious
            if suspicious > 0: return f"Suspicious: {suspicious}/{total} vendors flagged", suspicious
            return f"Clean: 0/{total} vendors flagged", 0
        return f"Error HTTP {response.status_code}", 0
    except Exception as e:
        return f"Error: {str(e)}", 0

def detect_brute_force(ip: str, log_data: str):
    pattern = rf"{re.escape(ip)}.*(?:denied|failed|invalid)"
    failures = len(re.findall(pattern, log_data, re.IGNORECASE))
    if failures >= 5: return f"Brute force detected! {failures} failed logins.", failures
    if failures > 0: return f"Suspicious: {failures} failed logins.", failures
    return "No brute force detected.", 0

def get_geo(ip: str):
    try:
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Private/Internal IP", True
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp", timeout=5)
        if response.status_code == 200 and response.json().get("status") == "success":
            d = response.json()
            return f"{d.get('city', 'Unknown')}, {d.get('country', 'Unknown')} (ISP: {d.get('isp', 'Unknown')})", False
        return "Geo lookup failed", False
    except:
        return "Error", False

def get_groq_summary(ip, abuse_info, vt_info, bf_info, geo_info):
    if not GROQ_API_KEY: return "GROQ API Key missing."
    prompt = f"""
    You are a SOC Investigation Analyst. Summarize the following threat intelligence into a clear, concise report.
    IP Address: {ip}
    1. AbuseIPDB: {abuse_info}
    2. VirusTotal: {vt_info}
    3. Brute Force Logs: {bf_info}
    4. Geolocation: {geo_info}
    Format your response as a numbered list with a final recommendation (Block or Monitor).
    """
    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3
            },
            timeout=10
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        return f"Groq Error: {response.text}"
    except Exception as e:
        return f"Groq Request Failed: {str(e)}"

if st.button("Analyze Logs", type="primary"):
    if not log_input.strip():
        st.warning("Please paste some firewall logs first.")
    else:
        ips = extract_ips(log_input)
        if not ips:
            st.error("No valid IP addresses found in the logs.")
        else:
            st.success(f"Found {len(ips)} unique IP addresses to investigate.")
            
            progress_bar = st.progress(0)
            
            for i, ip in enumerate(ips):
                with st.expander(f"🔍 Investigating IP: {ip}", expanded=True):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Gathering Threat Intelligence...**")
                        abuse_text, abuse_score = check_abuseipdb(ip)
                        st.write(f"- **AbuseIPDB:** {abuse_text}")
                        
                        vt_text, vt_score = check_virustotal(ip)
                        st.write(f"- **VirusTotal:** {vt_text}")
                        
                        bf_text, bf_count = detect_brute_force(ip, log_input)
                        st.write(f"- **Behavior:** {bf_text}")
                        
                        geo_text, is_priv = get_geo(ip)
                        st.write(f"- **Location:** {geo_text}")
                        
                    with col2:
                        st.markdown("**🤖 Groq LLM Analysis...**")
                        with st.spinner("Generating summary..."):
                            summary = get_groq_summary(ip, abuse_text, vt_text, bf_text, geo_text)
                            st.write(summary)
                            
                    # Final determination
                    is_malicious = abuse_score > 50 or vt_score > 0 or bf_count >= 5
                    status_class = "malicious" if is_malicious else "clean"
                    status_icon = "🔴 MALICIOUS" if is_malicious else "🟢 CLEAN"
                    
                    st.markdown(f"""
                    <div class="metric-card {status_class}">
                        <h3>{status_icon} - {ip}</h3>
                        <div class="metric-row"><div class="metric-label">Location:</div><div class="metric-value">{geo_text}</div></div>
                        <div class="metric-row"><div class="metric-label">Threat Score:</div><div class="metric-value">{abuse_score}/100</div></div>
                    </div>
                    """, unsafe_allow_html=True)
                
                progress_bar.progress((i + 1) / len(ips))
            
            st.balloons()
            st.success("Investigation Complete!")
