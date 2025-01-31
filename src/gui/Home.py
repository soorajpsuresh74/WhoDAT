import streamlit as st

from WhoDATLogger import setup_logger
from src.core.emailAnalysis.email_analysis import EmailAnalysis
from src.core.virusTotal.virusTotal import virus_total, virus_total_attachments

logger = setup_logger("Home.py")

app_title = 'WhoDAT Quickview'
st.set_page_config(page_title=app_title, page_icon=r'assets/images/cyber-security.png')

st.sidebar.title("Navigation")
app_mode = st.sidebar.radio("Select a Section",
                            ("Overview", "Email Analysis", "URL Analysis", "IP Analysis", "Attachment Analysis"))

st.title("WhoDAT - Cybersecurity Tool")
st.markdown("""
 * Use the menu on the left to select data and set plot parameters
 * Your plots will appear below
""")
st.header("Analyze Emails, URLs, IPs, and Attachments")

if app_mode == "Overview":
    st.subheader("Overview")
    st.text("Here is a quick overview of the tool's functionality.")
    st.text("You can upload files or enter URLs for analysis.")
    logger.info("User accessed the Overview section.")

elif app_mode == "Email Analysis":
    st.subheader("Email Analysis")
    email_input = st.text_input("Enter an email address:")
    uploaded_file = st.file_uploader("Upload an email file for analysis")

    if uploaded_file is not None:
        logger.info("Email file uploaded for analysis.")
        try:
            email_analysis = EmailAnalysis(uploaded_file)
            st.write("Metadata:", email_analysis.metadata)
            # st.write("Content:", email_analysis.content)
            # st.write("Links:", email_analysis.links)
            # st.write("Attachments:", email_analysis.attachments)

            if email_analysis.links:
                try:
                    logger.info(f"Scanning email links: {email_analysis.links}")
                    vt_result = virus_total(email_analysis.links)
                    st.subheader("VirusTotal Scan Results")
                    st.json(vt_result)
                    logger.info(f"VirusTotal results: {vt_result}")
                except Exception as e:
                    logger.error(f"Error during VirusTotal scan: {e}")
                    st.error(f"VirusTotal scan failed: {e}")
            else:
                st.info("No links found in the email for scanning.")

            if email_analysis.attachments:
                try:
                    logger.info(f"Scanning email attachments: {email_analysis.attachments}")
                    vt_result = virus_total_attachments(email_analysis.attachments)
                    st.subheader("VirusTotal Scan Results")
                    st.json(vt_result)
                    logger.info(f"VirusTotal results: {vt_result}")
                except Exception as e:
                    logger.error(f"Error during VirusTotal scan: {e}")
                    st.error(f"VirusTotal scan failed: {e}")



        except Exception as e:
            logger.error(f"Error processing email file: {e}")
            st.error(f"An error occurred: {e}")
    else:
        st.info("Please upload an email file to proceed.")

elif app_mode == "URL Analysis":
    st.subheader("URL Analysis")
    url_input = st.text_input("Enter a URL:")
    uploaded_file = st.file_uploader("Upload a file for analysis")
    analyze_button = st.button("Analyze URL")

    if analyze_button:
        logger.info(f"User clicked Analyze URL for {url_input}")
        if url_input:
            try:
                vt_result = virus_total([url_input])
                st.subheader("VirusTotal Scan Results")
                st.json(vt_result)
                logger.info(f"VirusTotal results for {url_input}: {vt_result}")
            except Exception as e:
                logger.error(f"Error scanning URL {url_input}: {e}")
                st.error(f"URL scan failed: {e}")
        else:
            st.warning("Please enter a URL to analyze.")

elif app_mode == "IP Analysis":
    st.subheader("IP Analysis")
    ip_input = st.text_input("Enter an IP address:")
    uploaded_file = st.file_uploader("Upload a file for analysis")
    analyze_button = st.button("Analyze IP")

    if analyze_button:
        logger.info(f"User clicked Analyze IP for {ip_input}")
        if ip_input:
            try:
                vt_result = virus_total([ip_input])
                st.subheader("VirusTotal Scan Results")
                st.json(vt_result)
                logger.info(f"VirusTotal results for {ip_input}: {vt_result}")
            except Exception as e:
                logger.error(f"Error scanning IP {ip_input}: {e}")
                st.error(f"IP scan failed: {e}")
        else:
            st.warning("Please enter an IP address to analyze.")

elif app_mode == "Attachment Analysis":
    st.subheader("Attachment Analysis")
    uploaded_file = st.file_uploader("Upload a file for attachment analysis")
    analyze_button = st.button("Analyze Attachment")

    if analyze_button:
        if uploaded_file:
            logger.info("User uploaded an attachment for analysis.")
            st.success("Attachment analysis is currently under development.")
        else:
            st.warning("Please upload an attachment first.")
