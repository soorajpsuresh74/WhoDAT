import asyncio
from src.main import run_gui_mode, run_cli_mode

if __name__ == "__main__":
    mode = input("Choose mode (GUI/CLI[Default]): ").strip().lower()

    if mode == "gui":
        run_gui_mode()
    elif mode == "cli":
        asyncio.run(run_cli_mode())
    else:
        print("Default mode!")
        asyncio.run(run_cli_mode())
