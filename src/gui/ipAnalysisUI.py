import config
import streamlit as st

from WhoDATLogger import setup_logger
from src.core.emailAnalysis.ipAddressAnalysis import ip_addresses_analysis

logger = setup_logger("ip_analysis_ui")


def ip_analysis_ui() -> None:
    st.subheader("IP Analysis")
    ip_input = st.text_input("Enter an IP address:")
    analyze_button = st.button("Analyze IP")

    if analyze_button:
        logger.info(f"User clicked Analyze IP for {ip_input}")
        if ip_input:
            try:
                vt_result = ip_addresses_analysis([ip_input])
                st.subheader("VirusTotal Scan Results")
                st.json(vt_result)
            except Exception as e:
                logger.error(f"Error scanning IP {ip_input}: {e}")
                st.error(f"IP scan failed: {e}")
        else:
            st.warning("Please enter an IP address to analyze.")


