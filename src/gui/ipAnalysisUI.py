import streamlit as st

from WhoDATLogger import setup_logger
from src.core.emailAnalysis.ipAddressAnalysis import ip_addresses_analysis, check_spf_dkim_dmarc

logger = setup_logger("ip_analysis_ui")

def ip_analysis_ui() -> None:
    """Streamlit UI for IP Analysis."""
    st.title("🔍 IP Address Security Analysis")

    ip_input = st.text_input("Enter an IP address:")
    analyze_ip_button = st.button("Analyze IP")

    if analyze_ip_button:
        logger.info(f"User clicked Analyze IP for {ip_input}")

        if ip_input:
            try:
                # Perform IP Analysis (VirusTotal, Geolocation, ISP)
                analysis_results = ip_addresses_analysis([ip_input])

                if analysis_results:
                    st.subheader("🛡 VirusTotal Scan Results")
                    for result in analysis_results:
                        st.write(f"**IP:** {result['ip']}")
                        st.write(f"**Malicious Detections:** {result['malicious']}")
                        st.write(f"**Suspicious Detections:** {result['suspicious']}")
                        st.write(f"**Harmless:** {result['harmless']}")
                        st.write(f"**Undetected:** {result['undetected']}")

                        st.subheader("🌍 Geolocation & ISP Info")
                        st.write(f"**City:** {result.get('city', 'N/A')}")
                        st.write(f"**Region:** {result.get('region', 'N/A')}")
                        st.write(f"**Country:** {result.get('country', 'N/A')}")
                        st.write(f"**ISP:** {result.get('isp', 'N/A')}")

                        flagged = "✅ **Safe**" if not result.get(
                            "flagged") else "🚨 **Flagged: Outside Allowed Country**"
                        st.write(f"**Flagged:** {flagged}")

                        st.markdown("---")

            except Exception as e:
                logger.error(f"Error scanning IP {ip_input}: {e}")
                st.error(f"IP scan failed: {e}")
        else:
            st.warning("Please enter an IP address to analyze.")

    # Domain input for SPF, DKIM, DMARC validation
    st.subheader("📧 Email Security Analysis")
    domain_input = st.text_input("Enter a domain for SPF/DKIM/DMARC Check:")
    analyze_domain_button = st.button("Analyze Domain")

    if analyze_domain_button:
        if domain_input:
            try:
                auth_results = check_spf_dkim_dmarc(domain_input)

                st.subheader("🔐 Authentication Records")
                st.write(f"**SPF:** {auth_results.get('SPF', 'Not Found')}")
                st.write(f"**DKIM:** {auth_results.get('DKIM', 'Not Found')}")
                st.write(f"**DMARC:** {auth_results.get('DMARC', 'Not Found')}")
            except Exception as e:
                logger.error(f"Error analyzing domain {domain_input}: {e}")
                st.error(f"Domain analysis failed: {e}")
        else:
            st.warning("Please enter a domain to analyze.")
