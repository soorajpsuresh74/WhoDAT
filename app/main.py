import logging
import uvicorn
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import os
import shutil
from pydantic import BaseModel

from core.EmailAnlaysis import analyze_email_main

try:
    import config
    HOST = config.HOST
    PORT = config.PORT
    PROTOCOL = config.PROTOCOL
except ImportError:
    logging.warning("Config file not found, using default values.")
    HOST = "127.0.0.1"
    PORT = 8000
    PROTOCOL = "http"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = FastAPI()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class AnalyzeRequest(BaseModel):
    filename: str

@app.get("/")
def root():
    return {"message": "Hello from WhoDAT backend!"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/upload-email")
async def upload_email(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        return {"filename": file.filename, "message": "File uploaded successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

@app.post("/analyze-email")
def analyze_email(request: AnalyzeRequest):
    file_path = os.path.join(UPLOAD_DIR, request.filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    investigation = True
    analyze_result = analyze_email_main(file_path, investigation)

    result = {
        "Filename": request.filename,
        "Headers": analyze_result['Headers'],
        "Digests": analyze_result['Digests'],
        "Links": analyze_result['Links'],
        "Attachments": analyze_result['Attachments'],
    }

    logging.info(f"Analysis completed for: {request.filename}")
    return result

@app.post("/upload-attachment")
async def upload_attachment(attachment: UploadFile = File(...)):
    try:
        file_location = os.path.join(UPLOAD_DIR, attachment.filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(attachment.file, buffer)

        logging.info(f"Attachment uploaded: {attachment.filename}")
        return JSONResponse(content={"filename": attachment.filename, "status": "uploaded"})
    except Exception as e:
        logging.error(f"Error uploading attachment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error uploading attachment: {str(e)}")

class AnalyzeAttachmentRequest(BaseModel):
    filename: str

@app.post("/analyze-attachment")
async def analyze_attachment(request: AnalyzeAttachmentRequest):
    try:
        file_location = os.path.join(UPLOAD_DIR, request.filename)

        if not os.path.isfile(file_location):
            raise HTTPException(status_code=404, detail="File not found")

        analysis_result = {
            "filename": request.filename,
            "analysis": "Attachment analysis complete. (You can add real analysis logic here.)"
        }
        return JSONResponse(content=analysis_result)
    except Exception as e:
        logging.error(f"Error analyzing attachment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing attachment: {str(e)}")
if __name__ == "__main__":
    logging.info(f"Starting server at {PROTOCOL}://{HOST}:{PORT}")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
