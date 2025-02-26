import os
import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from config import logger  # Assuming you have a logger setup
from core.AttachmentAnalysis import virus_total_attachment_analysis

# Directory to store uploaded files
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

router = APIRouter()

class AnalyzeAttachmentRequest(BaseModel):
    filename: str

@router.post("/upload-attachment")
async def upload_attachment(file: UploadFile = File(...)):
    try:
        file_path = Path(UPLOAD_DIR) / file.filename
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info(f"📂 File saved: {file.filename}")
        return {"filename": file.filename, "message": "File uploaded successfully"}
    except Exception as e:
        logger.error(f"❌ Error saving file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")

@router.post("/analyze-attachment")
async def analyze_attachment(request: AnalyzeAttachmentRequest):
    try:
        file_path = Path(UPLOAD_DIR) / request.filename

        if not file_path.exists():
            logger.warning(f"⚠️ File not found: {request.filename}")
            raise HTTPException(status_code=404, detail=f"File not found: {request.filename}")

        # Read file content and pass as a tuple (filename, file_data)
        with file_path.open("rb") as f:
            file_data = f.read()

        analysis_result = virus_total_attachment_analysis((request.filename, file_data))

        logger.info(f"🔍 Analysis completed for {request.filename}")
        return JSONResponse(content={"filename": request.filename, "analysis": analysis_result})
    except Exception as e:
        logger.error(f"❌ Error analyzing attachment: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing attachment: {str(e)}")