import streamlit as st
import requests
from WhoDATLogger import setup_logger
from src.core.URLScanIO.wesiteAnalysis import website_analysis

logger = setup_logger("website_analysis_ui")

def download_image(image_url):
    """Fetch image from URL and return as bytes."""
    try:
        response = requests.get(image_url, stream=True)
        if response.status_code == 200:
            return response.content
        else:
            st.error("Failed to download image.")
            return None
    except Exception as e:
        st.error(f"Error downloading image: {e}")
        return None

def website_analysis_ui() -> None:
    st.subheader("Website Analysis")
    website_input = st.text_input("Enter a Website URL:")
    analyze_button = st.button("Analyze Website")

    if analyze_button:
        logger.info(f"User clicked Analyze Website for {website_input}")
        if website_input:
            try:
                vt_result = website_analysis([website_input])

                if vt_result:
                    st.subheader("URLScanIO Scan Results")
                    st.json(vt_result)

                    # Extract Screenshot URL
                    screenshot_url = vt_result[0].get("screenshot")

                    if screenshot_url and screenshot_url != "Not Available":
                        st.image(screenshot_url, caption="Website Screenshot", use_column_width=True)

                        # Download Button
                        image_bytes = download_image(screenshot_url)
                        if image_bytes:
                            st.download_button(
                                label="Download Screenshot",
                                data=image_bytes,
                                file_name="website_screenshot.png",
                                mime="image/png"
                            )
            except Exception as e:
                logger.error(f"Error scanning {website_input}: {e}")
                st.error(f"URLScanIO scan failed: {e}")
        else:
            st.warning("Please enter a Website address to analyze.")
