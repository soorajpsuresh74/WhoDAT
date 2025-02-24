import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from core.DMARCAnalysis import fetch_dmarc_record


router = APIRouter()

class AnalyzeDMARCRequest(BaseModel):
    domain: str

@router.post("/analyze-dmarc")
async def analyze_dmarc(request: AnalyzeDMARCRequest):
    response = fetch_dmarc_record(request.domain)
    return response