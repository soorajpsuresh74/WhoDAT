import json
import os
import io
from WhoDATLogger import setup_logger
from src.core.emailAnalysis.email_analysis import EmailAnalysis
from src.core.virusTotal.virusTotal import virus_total

logger = setup_logger("email_analysis_cli")


def email_analysis_cli():
    """Run Email Analysis in CLI Mode"""
    print("\n📧 Email Analysis - CLI Mode")

    file_path = input("📂 Enter the path of the email (.eml) file: ").strip()

    if not os.path.exists(file_path):
        print("❌ Error: File not found. Please check the path and try again.")
        return

    try:
        with open(file_path, "rb") as f:
            uploaded_file = io.BytesIO(f.read())  # Convert bytes to file-like object

        # Run Email Analysis
        email_analysis = EmailAnalysis(uploaded_file)  # ✅ Now a file-like object
        analysis_result = email_analysis.get_analysis()

        # 📌 Print Metadata
        print("\n📝 Email Metadata:")
        print(json.dumps(analysis_result["Metadata"], indent=4))

        # 📌 Print Sender Domain Status
        print(f"\n🔍 Sender Domain Classification: {analysis_result['Sender Domain Status']}")

        # 📌 Extracted Links & VirusTotal Scan
        if analysis_result["Links"]:
            print("\n🔗 Extracted Links:")
            for link in analysis_result["Links"]:
                print(f"- {link}")

            # Run VirusTotal scan
            try:
                logger.info(f"Scanning email links: {analysis_result['Links']}")
                vt_result = virus_total(analysis_result["Links"])
                print("\n🦠 VirusTotal Scan Results:")
                print(json.dumps(vt_result, indent=4))
            except Exception as e:
                logger.error(f"Error during VirusTotal scan: {e}")
                print(f"❌ VirusTotal scan failed: {e}")
        else:
            print("\n✅ No links found in the email.")

        # 📌 Print Attachments
        if analysis_result["Attachments"]:
            print("\n📎 Email Attachments:")
            for attachment in email_analysis.attachments:
                filename, content = attachment
                print(f"- {filename} (saved locally)")
                with open(filename, "wb") as f:
                    f.write(content)  # Save the attachment
        else:
            print("\n✅ No attachments found.")

        # 📌 Save Analysis to JSON File
        output_filename = "email_analysis.json"
        with open(output_filename, "w") as json_file:
            json.dump(analysis_result, json_file, indent=4)

        print(f"\n📥 Analysis saved as {output_filename}")

    except Exception as e:
        logger.error(f"Error processing email file: {e}")
        print(f"❌ An error occurred: {e}")

