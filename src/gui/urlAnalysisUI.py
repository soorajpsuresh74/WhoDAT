import streamlit as st
from WhoDATLogger import setup_logger
from src.core.virusTotal.virusTotal import virus_total_attachments, virus_total

logger = setup_logger("url_analysis_ui")

def url_analysis_ui()-> None:
    st.subheader("URL Analysis")
    url_input = st.text_input("Enter a URL:")
    analyze_button = st.button("Analyze URL")

    if analyze_button:
        logger.info(f"User clicked Analyze URL for {url_input}")
        if url_input:
            try:
                vt_result = virus_total([url_input])
                st.subheader("VirusTotal Scan Results")
                st.json(vt_result)
            except Exception as e:
                logger.error(f"Error scanning URL {url_input}: {e}")
                st.error(f"URL scan failed: {e}")
        else:
            st.warning("Please enter a URL to analyze.")