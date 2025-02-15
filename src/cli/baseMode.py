import pyfiglet
from src.core.emailAnalysis.emailAnalysisCLI import email_analysis_cli

async def base_mode():
    """Display ASCII art and menu options in a loop until the user chooses to exit."""
    ascii_art = pyfiglet.figlet_format("WhoDAT")
    print(ascii_art)
    print("--------------------------------------")

    while True:
        print("\n📌 Select a mode to run:")
        print("1️⃣ Email Analysis")
        print("2️⃣ URL Analysis")
        print("3️⃣ IP Analysis")
        print("4️⃣ Attachment Analysis")
        print("5️⃣ Website Analysis")
        print("6️⃣ Whois Analysis")
        print("7️⃣ DMARC Analysis")
        print("8️⃣ Exit")

        choice = input("\nEnter your choice (1-8): ").strip()

        if choice == '1':
            email_analysis_cli()
        elif choice == '8':
            print("🚪 Exiting WhoDAT... Goodbye! 👋")
            break
        else:
            print("⚠️ Invalid choice. Please enter a number between 1 and 8.")

