import streamlit as st
from WhoDATLogger import setup_logger
from src.core.emailAnalysis.email_analysis import EmailAnalysis
from src.core.virusTotal.virusTotal import virus_total

logger = setup_logger("email_analysis_ui")

def email_analysis_ui():
    st.subheader("Email Analysis")
    uploaded_file = st.file_uploader("Upload an email file for analysis", key="email_upload")

    if uploaded_file is not None and uploaded_file != st.session_state.uploaded_email_file:
        st.session_state.uploaded_email_file = uploaded_file
        logger.info("New email file uploaded for analysis.")

        try:
            email_analysis = EmailAnalysis(uploaded_file)
            st.write("Metadata:", email_analysis.metadata)

            if email_analysis.links:
                try:
                    logger.info(f"Scanning email links: {email_analysis.links}")
                    vt_result = virus_total(email_analysis.links)
                    st.subheader("VirusTotal Scan Results")
                    st.json(vt_result)
                except Exception as e:
                    logger.error(f"Error during VirusTotal scan: {e}")
                    st.error(f"VirusTotal scan failed: {e}")
            else:
                st.info("No links found in the email for scanning.")

        except Exception as e:
            logger.error(f"Error processing email file: {e}")
            st.error(f"An error occurred: {e}")
    elif uploaded_file is None:
        st.info("Please upload an email file to proceed.")