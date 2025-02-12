import streamlit as st
import dns.resolver
from WhoDATLogger import setup_logger

# Initialize Logger
logger = setup_logger("dmarc_analysis_ui")


def fetch_dmarc_record(domain: str):
    """Fetch the DMARC record of a given domain."""
    try:
        dmarc_query = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_query, "TXT")
        for rdata in answers:
            return rdata.to_text()
    except Exception as e:
        logger.error(f"Error fetching DMARC record for {domain}: {e}")
        return None


def parse_dmarc_record(dmarc_record: str):
    """Extracts important DMARC fields from the record."""
    dmarc_data = {}
    if dmarc_record:
        tags = dmarc_record.strip('"').split(";")
        for tag in tags:
            key_value = tag.strip().split("=")
            if len(key_value) == 2:
                dmarc_data[key_value[0].strip()] = key_value[1].strip()
    return dmarc_data


def dmarc_analysis_ui():
    """Streamlit UI for DMARC Record Analysis."""
    st.title("📧 DMARC Record Analysis")

    # User input
    domain_input = st.text_input("Enter a domain for DMARC lookup:")
    check_dmarc_button = st.button("Check DMARC")

    if check_dmarc_button:
        logger.info(f"User initiated DMARC check for {domain_input}")

        if domain_input:
            dmarc_record = fetch_dmarc_record(domain_input)

            if dmarc_record:
                st.subheader("🔍 DMARC Record Found")
                st.code(dmarc_record, language="txt")

                # Parse and display DMARC components
                dmarc_data = parse_dmarc_record(dmarc_record)

                st.subheader("📜 DMARC Policy Details")
                st.write(f"**Policy (p):** {dmarc_data.get('p', 'Not Found')}")
                st.write(f"**Subdomain Policy (sp):** {dmarc_data.get('sp', 'Not Found')}")
                st.write(f"**Reporting Email (rua):** {dmarc_data.get('rua', 'Not Found')}")
                st.write(f"**Failure Reports (ruf):** {dmarc_data.get('ruf', 'Not Found')}")
                st.write(f"**Failure Percentage (pct):** {dmarc_data.get('pct', '100')}")
                st.write(
                    f"**Alignment Mode (aspf/dkim):** {dmarc_data.get('aspf', 'Not Found')}, {dmarc_data.get('adkim', 'Not Found')}")
            else:
                st.error("No DMARC record found for this domain.")
        else:
            st.warning("Please enter a domain for DMARC lookup.")

