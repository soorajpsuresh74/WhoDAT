import asyncio
import os

from src.main import run_gui_mode, run_cli_mode

if __name__ == "__main__":
    # mode = os.getenv("APP_MODE", "cli").strip().lower()
    mode = input("Choose mode (GUI/CLI[Default]): ").strip().lower()

    if mode == "gui":
        print("Starting in GUI mode...")
        run_gui_mode()
    elif mode == "cli":
        print("Starting in CLI mode...")
        asyncio.run(run_cli_mode())
    else:
        print("Default mode!")
        asyncio.run(run_cli_mode())
