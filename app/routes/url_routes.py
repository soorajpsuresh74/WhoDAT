import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from core.URLAnalyzes import virus_total_link_analysis

router = APIRouter()

class AnalyzeURLRequest(BaseModel):
    url: str

@router.post("/analyze-url")
async def analyze_url(request: AnalyzeURLRequest):
    response = virus_total_link_analysis(request.url)
    return response