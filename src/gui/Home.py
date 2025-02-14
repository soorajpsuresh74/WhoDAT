import streamlit as st

from WhoDATLogger import setup_logger
from src.gui.Dmarc import dmarc_analysis_ui
from src.gui.attachmentAnalysisUI import attachment_analysis_ui
from src.gui.emailAnalysisUI import email_analysis_ui
from src.gui.ipAnalysisUI import ip_analysis_ui
from src.gui.urlAnalysisUI import url_analysis_ui
from src.gui.websiteAnalysisUI import website_analysis_ui
from src.gui.whoIsScan import whois_analysis_ui

logger = setup_logger("Home.py")

app_title = 'WhoDAT Quickview'
st.set_page_config(page_title=app_title, page_icon=r'assets/images/cyber-security.png')

st.sidebar.title("Navigation")
app_mode = st.sidebar.radio("Select a Section",
                            ("Overview", "Email Analysis", "URL Analysis", "IP Analysis", "Attachment Analysis", "Website Analysis", "Whois Analysis", "DMARC Analysis"))

st.title("WhoDAT - Cybersecurity Tool")


if "uploaded_email_file" not in st.session_state:
    st.session_state.uploaded_email_file = None

if "uploaded_attachment_file" not in st.session_state:
    st.session_state.uploaded_attachment_file = None

if app_mode == "Overview":
    st.subheader("Overview")
    st.text("Quick overview of the tool's functionality.")
    st.markdown("""
     * Use the menu on the left to select data and set plot parameters
     * Your results will appear below.
    """)
    st.header("Analyze Emails, URLs, IPs, and Attachments")
    logger.info("User accessed the Overview section.")

elif app_mode == "Email Analysis":
    email_analysis_ui()


elif app_mode == "URL Analysis":
    url_analysis_ui()

elif app_mode == "IP Analysis":
    ip_analysis_ui()


elif app_mode == "Attachment Analysis":
    attachment_analysis_ui()

elif app_mode == "Website Analysis":
    website_analysis_ui()

elif app_mode == "Whois Analysis":
    whois_analysis_ui()

elif app_mode == "DMARC Analysis":
    dmarc_analysis_ui()



