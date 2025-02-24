import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from core.WebsiteAnalysis import website_analysis


router = APIRouter()

class AnalyzeWebsiteRequest(BaseModel):
    website: str

@router.post("/analyze-website")
async def analyze_url(request: AnalyzeWebsiteRequest):
    print(request.website)
    response = website_analysis(request.website)
    return response