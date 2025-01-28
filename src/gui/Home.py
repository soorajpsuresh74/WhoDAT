import streamlit as st

from src.core.emailAnalysis.email_analysis import EmailAnalysis

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

elif app_mode == "Email Analysis":
    st.subheader("Email Analysis")
    st.text_input("Enter an email address:")
    uploaded_file = st.file_uploader("Upload an email file for analysis")
    if uploaded_file is not None:
        try:
            email_analysis = EmailAnalysis(uploaded_file)
            st.write("Metadata:", email_analysis.metadata)
            st.write("Content:", email_analysis.content)
            st.write("Links:", email_analysis.links)
            st.write("Attachments:", email_analysis.attachments)
        except Exception as e:
            st.error(f"An error occurred: {e}")
    else:
        st.info("Please upload an email file to proceed.")

elif app_mode == "URL Analysis":
    st.subheader("URL Analysis")
    st.text_input("Enter a URL:")
    uploaded_file = st.file_uploader("Upload a file for analysis")
    st.button("Analyze URL")

elif app_mode == "IP Analysis":
    st.subheader("IP Analysis")
    st.text_input("Enter an IP address:")
    uploaded_file = st.file_uploader("Upload a file for analysis")
    st.button("Analyze IP")

elif app_mode == "Attachment Analysis":
    st.subheader("Attachment Analysis")
    uploaded_file = st.file_uploader("Upload a file for attachment analysis")
    st.button("Analyze Attachment")

