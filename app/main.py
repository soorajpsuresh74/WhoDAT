import logging

import uvicorn
from fastapi import FastAPI
import config

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello from WhoDAT backend!"}

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host=config.HOST, port= config.PORT, reload=True)
    logging.info(f"Main started with {config.PROTOCOL}://{config.HOST}:{config.PORT}")
