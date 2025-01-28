import subprocess


async def main() -> None:
    try:
        subprocess.run(["streamlit", "run", "src/gui/Home.py"], check=True)
    except FileNotFoundError:
        print("Streamlit command not found. Ensure it is installed and in your PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Streamlit exited with an error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

