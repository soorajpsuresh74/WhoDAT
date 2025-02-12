import streamlit as st
from WhoDATLogger import setup_logger
from src.core.virusTotal.virusTotal import virus_total_attachments, virus_total
import requests
import config

logger = setup_logger("url_analysis_ui")

VT_IP_SCAN_ENDPOINT = config.MySecret.VT_IP_SCAN_ENDPOINT
VT_URL_SCAN_ENDPOINT = config.MySecret.VIRUS_TOTAL_ENDPOINT
headers = {"x-apikey": config.MySecret.VIRUS_TOTAL_KEY}

def analyze_ip(ip_address):
    """Check if an IP address has been associated with malicious activity."""
    try:
        logger.info(f"Scanning IP Address: {ip_address}")
        response = requests.get(f"{VT_IP_SCAN_ENDPOINT}/{ip_address}", headers=headers)

        if response.status_code == 200:
            data = response.json()
            analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "IP": ip_address,
                "Malicious": analysis.get('malicious', 0),
                "Suspicious": analysis.get('suspicious', 0),
                "Harmless": analysis.get('harmless', 0),
                "Undetected": analysis.get('undetected', 0)
            }
        else:
            return {"IP": ip_address, "Error": f"Error {response.status_code}", "Response": response.json()}
    except Exception as e:
        logger.error(f"Error analyzing IP {ip_address}: {e}")
        return {"IP": ip_address, "Error": str(e)}

def url_analysis_ui() -> None:
    st.subheader("Security Scanner")

    # URL Analysis Section
    st.write("### URL Analysis")
    url_input = st.text_input("Enter a URL:")
    analyze_url_button = st.button("Analyze URL")

    if analyze_url_button:
        logger.info(f"User clicked Analyze URL for {url_input}")
        if url_input:
            try:
                vt_result = virus_total([url_input])
                st.subheader("VirusTotal URL Scan Results")
                st.json(vt_result)
            except Exception as e:
                logger.error(f"Error scanning URL {url_input}: {e}")
                st.error(f"URL scan failed: {e}")
        else:
            st.warning("Please enter a URL to analyze.")

    # IP Address Analysis Section
    st.write("---")  # Separator
    st.write("### IP Address Analysis")
    ip_input = st.text_input("Enter an IP Address:")
    analyze_ip_button = st.button("Analyze IP")

    if analyze_ip_button:
        logger.info(f"User clicked Analyze IP for {ip_input}")
        if ip_input:
            try:
                ip_result = analyze_ip(ip_input)
                st.subheader("VirusTotal IP Analysis Results")
                st.json(ip_result)
            except Exception as e:
                logger.error(f"Error scanning IP {ip_input}: {e}")
                st.error(f"IP scan failed: {e}")
        else:
            st.warning("Please enter an IP address to analyze.")
