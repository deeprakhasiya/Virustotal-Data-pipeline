from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import os
from dotenv import load_dotenv

from database import connect_to_mongo, close_mongo_connection, get_database
from schemas import VirusTotalReportResponse , ResourceRequest
from vt_client import VirusTotalClient
from db_manager import DBManager

load_dotenv()

app = FastAPI(title="VirusTotal Data Pipeline", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize managers
vt_client = VirusTotalClient()
db_manager = DBManager()

@app.on_event("startup")
async def startup_event():
    await connect_to_mongo()
    print("Connected to MongoDB successfully!")
    print("Server starting on http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")

@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()

@app.get("/")
async def root():
    return {"message": "VirusTotal Data Pipeline API"}


@app.get("/report", response_model=VirusTotalReportResponse)
async def get_report(data: ResourceRequest):
    """Get domain report from VirusTotal with caching"""

    report = None
    if data.resource_type == "domain":
        report = await get_domain_report(data.value)
    elif data.resource_type == "hash":
        report = await get_file_report(data.value)
    elif data.resource_type == "ip":
        report = await get_ip_report(data.value)
    else:
        raise HTTPException(status_code=400, detail="Invalid resource type")

    return report

@app.get("/refresh", response_model=VirusTotalReportResponse)
async def get_report(data: ResourceRequest):
    """Get domain report from VirusTotal with caching"""

    report = None
    if data.resource_type == "domain":
        report = await refresh_domain_report(data.value)
    elif data.resource_type == "hash":
        report = await refresh_file_report(data.value)
    elif data.resource_type == "ip":
        report = await refresh_ip_report(data.value)
    else:
        raise HTTPException(status_code=400, detail="Invalid resource type")
    return report

async def get_domain_report(domain: str):
    """Get domain report from VirusTotal with caching"""
    db = get_database()
    report = await db.reports.find_one({
        "resource_id": domain,
        "resource_type": "domain"
    })

    if report:
        return report
    
    # Fetch from VirusTotal
    vt_data = vt_client.get_domain_report(domain)
    if not vt_data:
        raise HTTPException(status_code=404, detail="Domain not found in VirusTotal")
    
    # Store in db
    report = await db_manager.store_report(domain, "domain", vt_data)
    
   
    return report


async def get_ip_report(ip_address: str):
    """Get IP address report from VirusTotal with caching"""
 
    
    db = get_database()
    report = await db.reports.find_one({
        "resource_id": ip_address,
        "resource_type": "ip"
    })

    if report:
        return report
    
    vt_data = vt_client.get_ip_report(ip_address)
    if not vt_data:
        raise HTTPException(status_code=404, detail="IP address not found in VirusTotal")
    
    report = await db_manager.store_report(ip_address, "ip", vt_data)
    
    
    return report


async def get_file_report(file_hash: str):
    """Get file hash report from VirusTotal with caching"""
   
    
    db = get_database()
    report = await db.reports.find_one({
        "resource_id": file_hash,
        "resource_type": "hash"
    })

    if report:
        return report
    
    vt_data = vt_client.get_file_report(file_hash)
    if not vt_data:
        raise HTTPException(status_code=404, detail="File hash not found in VirusTotal")
    
    report = await db_manager.store_report(file_hash, "hash", vt_data)
    
   
    
    return report




async def refresh_domain_report(domain: str):
    """Force refresh domain report (bypass cache)"""
    vt_data = vt_client.get_domain_report(domain)
    if not vt_data:
        raise HTTPException(status_code=404, detail="Domain not found in VirusTotal")
    
    report = await db_manager.store_report(domain, "domain", vt_data)
    return report

async def refresh_ip_report(ip_address: str):
    """Force refresh IP report (bypass cache)"""
    vt_data = vt_client.get_ip_report(ip_address)
    if not vt_data:
        raise HTTPException(status_code=404, detail="IP address not found in VirusTotal")
    
    report = await db_manager.store_report(ip_address, "ip", vt_data)
    return report

async def refresh_file_report(file_hash: str):
    """Force refresh file report (bypass cache)"""
    vt_data = vt_client.get_file_report(file_hash)
    if not vt_data:
        raise HTTPException(status_code=404, detail="File hash not found in VirusTotal")
    
    report = await db_manager.store_report(file_hash, "hash", vt_data)
    return report


@app.get("/reports", response_model=List[VirusTotalReportResponse])
async def get_all_reports(skip: int = 0, limit: int = 100):
    """Get all stored reports with pagination"""
    db = get_database()
    cursor = db.reports.find().skip(skip).limit(limit)
    reports = await cursor.to_list(length=limit)
    return reports


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")