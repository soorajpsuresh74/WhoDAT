import logging
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

router = APIRouter()

class AnalyzeIPRequest(BaseModel):
    ip: str = Field(..., title="IP Address", description="The IP address to analyze")

def mock_ip_analysis(ip: str):
    """Mock function to simulate IP analysis."""
    if ip == "127.0.0.1":
        return {
            "ip": ip,
            "geolocation": "Localhost",
            "blacklist_status": "Safe"
        }
    elif ip == "8.8.8.8":
        return {
            "ip": ip,
            "geolocation": "USA, California",
            "blacklist_status": "Not Blacklisted"
        }
    else:
        return {
            "ip": ip,
            "geolocation": "Unknown",
            "blacklist_status": "Not Checked"
        }

@router.post("/analyze-ip")
async def analyze_ip(request: AnalyzeIPRequest):
    try:
        analysis_result = mock_ip_analysis(request.ip)
        return JSONResponse(content=analysis_result, status_code=200)
    except Exception as e:
        logging.error(f"Error analyzing IP: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
