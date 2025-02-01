import streamlit as st
from WhoDATLogger import setup_logger
from src.core.URLScanIO.wesiteAnalysis import website_analysis

logger = setup_logger("website_analysis_ui")

def website_analysis_ui() -> None:
    st.subheader("Website Analysis")
    website_input = st.text_input("Enter an IP address:")
    analyze_button = st.button("Analyze Website")

    if analyze_button:
        logger.info(f"User clicked Analyze Website for {website_input}")
        if website_input:
            try:
                vt_result = website_analysis([website_input])
                st.subheader("URLScanIO Scan Results")
                st.json(vt_result)
            except Exception as e:
                logger.error(f"Error scanning IP {website_input}: {e}")
                st.error(f"URLScanIO scan failed: {e}")
        else:
            st.warning("Please enter Website address to analyze.")
