import streamlit as st
import json
from WhoDATLogger import setup_logger
from src.core.emailAnalysis.email_analysis import EmailAnalysis
from src.core.virusTotal.virusTotal import virus_total

logger = setup_logger("email_analysis_ui")


def email_analysis_ui():
    st.subheader("📧 Email Analysis")

    uploaded_file = st.file_uploader("Upload an email file for analysis", type=["eml"], key="email_upload")

    if uploaded_file is not None and uploaded_file != st.session_state.get("uploaded_email_file"):
        st.session_state.uploaded_email_file = uploaded_file
        logger.info("New email file uploaded for analysis.")

        try:
            email_analysis = EmailAnalysis(uploaded_file)
            analysis_result = email_analysis.get_analysis()

            # 📌 Display Metadata
            st.write("### 📝 Email Metadata")
            st.json(analysis_result["Metadata"])

            # 📌 Display Sender Domain Classification
            st.write("### 🔍 Sender Domain Status")
            st.info(f"**Sender Domain Classification:** {analysis_result['Sender Domain Status']}")

            # 📌 Display Extracted Links & Scan them using VirusTotal
            if analysis_result["Links"]:
                st.write("### 🔗 Extracted Links")
                for link in analysis_result["Links"]:
                    st.markdown(f"- [{link}]({link})")

                try:
                    logger.info(f"Scanning email links: {analysis_result['Links']}")
                    vt_result = virus_total(analysis_result["Links"])
                    st.write("### 🦠 VirusTotal Scan Results")
                    st.json(vt_result)
                except Exception as e:
                    logger.error(f"Error during VirusTotal scan: {e}")
                    st.error(f"VirusTotal scan failed: {e}")
            else:
                st.info("No links found in the email.")

            # 📌 Display Attachments with Download Option
            if analysis_result["Attachments"]:
                st.write("### 📎 Email Attachments")
                for attachment in email_analysis.attachments:
                    filename, content = attachment
                    st.download_button(
                        label=f"Download {filename}",
                        data=content,
                        file_name=filename,
                        mime="application/octet-stream",
                    )
            else:
                st.info("No attachments found.")

            # 📌 Download Full Analysis as JSON
            st.write("### 📥 Export Analysis")
            st.download_button(
                label="Download Full Analysis as JSON",
                data=json.dumps(analysis_result, indent=4),
                file_name="email_analysis.json",
                mime="application/json",
            )

        except Exception as e:
            logger.error(f"Error processing email file: {e}")
            st.error(f"An error occurred: {e}")
    else:
        st.info("Please upload an email file to proceed.")
