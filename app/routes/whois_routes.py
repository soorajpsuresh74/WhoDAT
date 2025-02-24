import os
import shutil
import logging
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from core.ip2whois import whois_analysis

router = APIRouter()

class AnalyzeWhoRequest(BaseModel):
    domain: str

@router.post("/analyze-whois")
async def whois(request: AnalyzeWhoRequest):
    response = whois_analysis(request.domain)
    return response