import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

router = APIRouter()

class AnalyzeAttachmentRequest(BaseModel):
    filename: str

@router.post("/upload-attachment")
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

@router.post("/analyze-attachment")
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
