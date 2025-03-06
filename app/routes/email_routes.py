import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from core.EmailAnlaysis import analyze_email_main
from core.models.spamMailDetection import email_to_spam_ham

from core.models.ToxicCommentPredictor import classify_new_email_to_toxic

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

        logger.info(f"File uploaded: {file.filename}")
        return {"filename": file.filename, "message": "File uploaded successfully"}

    except Exception as e:
        logger.error(f"File upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")


@router.post("/analyze-email")
def analyze_email(request: AnalyzeRequest):
    file_path = os.path.join(UPLOAD_DIR, request.filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        investigation = True
        analyze_result = analyze_email_main(file_path, investigation)

        email_body = analyze_result.get('Body', "")
        spam_prediction = email_to_spam_ham(email_body)
        toxic_comment_prediction = classify_new_email_to_toxic(email_body)

        result = {
            "Filename": request.filename,
            "Headers": analyze_result.get('Headers', {}),
            "Digests": analyze_result.get('Digests', {}),
            "Links": analyze_result.get('Links', []),
            "Attachments": analyze_result.get('Attachments', []),
            "Body": email_body,
            "Toxic Prediction": toxic_comment_prediction,
            "Spam Prediction": spam_prediction
        }

        logger.info(f"Analysis completed for {request.filename}")
        return result

    except Exception as e:
        logger.error(f"Error analyzing email {request.filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
