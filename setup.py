import asyncio

from src.main import main


async def temp_setup() -> None:
    """This is a temp entry point"""
    await main()


if __name__ == "__main__":
    asyncio.run(temp_setup())
