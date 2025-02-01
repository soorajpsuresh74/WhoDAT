import streamlit as st

from WhoDATLogger import setup_logger
from src.core.virusTotal.virusTotal import virus_total_attachments

logger = setup_logger("attachment_analysis_ui")

def attachment_analysis_ui() -> None:
    st.subheader("Attachment Analysis")
    uploaded_file = st.file_uploader("Upload a file for attachment analysis", key="attachment_upload")
    analyze_button = st.button("Analyze Attachment")

    if uploaded_file is not None and uploaded_file != st.session_state.uploaded_attachment_file:
        st.session_state.uploaded_attachment_file = uploaded_file
        print(type(uploaded_file))
        logger.info(f"New attachment uploaded: {uploaded_file}")

    if analyze_button:
        if st.session_state.uploaded_attachment_file:
            logger.info(f"Analyzing attachment: {st.session_state.uploaded_attachment_file.name}")
            vt_result = virus_total_attachments([st.session_state.uploaded_attachment_file])
            st.subheader("VirusTotal Scan Results")
            st.json(vt_result)
        else:
            st.warning("Please upload an attachment first.")