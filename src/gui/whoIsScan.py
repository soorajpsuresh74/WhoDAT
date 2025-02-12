import streamlit as st
import whois
from WhoDATLogger import setup_logger

# Initialize Logger
logger = setup_logger("whois_analysis_ui")

def whois_analysis_ui() -> None:
    """Streamlit UI for WHOIS Domain Analysis."""
    st.title("🌐 WHOIS Domain Analysis")

    # User input
    domain_input = st.text_input("Enter a domain for WHOIS lookup:")
    analyze_button = st.button("Perform WHOIS Lookup")

    if analyze_button:
        logger.info(f"User initiated WHOIS lookup for {domain_input}")

        if domain_input:
            try:
                # Perform WHOIS lookup
                whois_data = whois.whois(domain_input)

                st.subheader("🔍 WHOIS Lookup Results")
                st.write(f"**Domain Name:** {whois_data.domain_name}")
                st.write(f"**Registrar:** {whois_data.registrar}")
                st.write(f"**Creation Date:** {whois_data.creation_date}")
                st.write(f"**Expiration Date:** {whois_data.expiration_date}")
                st.write(f"**Updated Date:** {whois_data.updated_date}")
                st.write(f"**Name Servers:** {', '.join(whois_data.name_servers) if whois_data.name_servers else 'N/A'}")
                st.write(f"**Status:** {whois_data.status}")
                st.write(f"**Emails:** {whois_data.emails}")

            except Exception as e:
                logger.error(f"Error fetching WHOIS data for {domain_input}: {e}")
                st.error(f"WHOIS lookup failed: {e}")
        else:
            st.warning("Please enter a domain name for WHOIS lookup.")

# Run the UI
if __name__ == "__main__":
    whois_analysis_ui()
