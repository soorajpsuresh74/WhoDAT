import logging
import uvicorn
from fastapi import FastAPI
from config.settings import HOST, PORT, PROTOCOL
from routes.email_routes import router as email_router
from routes.attachment_routes import router as attachment_router
from routes.ip_routes import router as ip_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello from WhoDAT backend!"}

@app.get("/health")
def health():
    return {"status": "healthy"}


app.include_router(email_router)
app.include_router(attachment_router)
app.include_router(ip_router)

if __name__ == "__main__":
    logging.info(f"Starting server at {PROTOCOL}://{HOST}:{PORT}")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
