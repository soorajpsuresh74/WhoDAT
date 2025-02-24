import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from core.EmailAnlaysis import analyze_email_main

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

router = APIRouter()

class AnalyzeRequest(BaseModel):
    filename: str

@router.post("/upload-email")
async def upload_email(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        return {"filename": file.filename, "message": "File uploaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

@router.post("/analyze-email")
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
