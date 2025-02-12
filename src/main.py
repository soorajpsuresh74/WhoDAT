import subprocess
from src.cli.baseMode import base_mode


async def run_cli_mode():
    """Runs the application in CLI mode."""
    await base_mode()


def run_gui_mode():
    """Runs the application in GUI mode (Streamlit)."""
    try:
        subprocess.run(["streamlit", "run", "src/gui/Home.py"], check=True)
    except FileNotFoundError:
        print("Streamlit command not found. Ensure it is installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Streamlit exited with an error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
