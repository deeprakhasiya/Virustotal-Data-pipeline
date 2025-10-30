from fastapi import FastAPI, HTTPException ,Depends ,BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List
import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select


from database import init_db, get_db, DomainReport, IPReport, HashReport, ResourceQueue
from schemas import VirusTotalReportResponse , ResourceRequest ,QueueItemResponse
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
    await init_db()
    print("Connected to MongoDB successfully!")
    print("Server starting on http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")

@app.get("/")
async def root():
    return {"message": "VirusTotal Data Pipeline API"}


@app.get("/report", response_model=VirusTotalReportResponse)
async def get_report(data: ResourceRequest, db: AsyncSession = Depends(get_db)):
    """Get domain report from VirusTotal with caching"""

    report = None
    if data.resource_type == "domain":
        report = await get_domain_report(data.value , db)
    elif data.resource_type == "hash":
        report = await get_file_report(data.value , db)
    elif data.resource_type == "ip":
        report = await get_ip_report(data.value , db)
    else:
        raise HTTPException(status_code=400, detail="Invalid resource type")

    return report


async def _get_or_queue_resource(db: AsyncSession, resource_type: str, resource_value: str, model_class):
    """Helper function to get resource or add to queue if not found"""
    # Query the respective table
    stmt = select(model_class).where(getattr(model_class, model_class.__table__.columns[1].name) == resource_value).order_by(model_class.created_at.desc())
    result = await db.execute(stmt)
    report = result.scalar_one_or_none()
    
    if report:
        # Return the report if found
        column_name = model_class.__table__.columns[1].name  # Get the second column name (domain, ip_address, or file_hash)
        return {
            "id": report.id,
            "resource_id": getattr(report, column_name),
            "resource_type": resource_type,
            "malicious": report.malicious,
            "suspicious": report.suspicious,
            "undetected": report.undetected,
            "harmless": report.harmless,
            "created_at": report.created_at
        }
    else:
        # Check if already in queue (not processed)
        stmt_queue = select(ResourceQueue).where(
            ResourceQueue.resource_type == resource_type,
            ResourceQueue.resource_value == resource_value,
            ResourceQueue.processed == False
        )
        result_queue = await db.execute(stmt_queue)
        existing_queue_item = result_queue.scalar_one_or_none()
        
        if existing_queue_item:
            raise HTTPException(
                status_code=404, 
                detail=f"{resource_type.capitalize()} '{resource_value}' not found in database. Already in processing queue with ID: {existing_queue_item.id}"
            )
        else:
            # Add to queue table if not found and not already in queue
            queue_item = ResourceQueue(
                resource_type=resource_type,
                resource_value=resource_value
            )
            db.add(queue_item)
            await db.commit()
            await db.refresh(queue_item)
            
            raise HTTPException(
                status_code=404, 
                detail=f"{resource_type.capitalize()} '{resource_value}' not found in database. Added to processing queue with ID: {queue_item.id}"
            )

async def get_domain_report(domain: str, db: AsyncSession):
    """Get domain report from PostgreSQL - if not found, add to queue"""
    return await _get_or_queue_resource(db, "domain", domain, DomainReport)

async def get_ip_report(ip_address: str, db: AsyncSession):
    """Get IP report from PostgreSQL - if not found, add to queue"""
    return await _get_or_queue_resource(db, "ip", ip_address, IPReport)

async def get_file_report(file_hash: str, db: AsyncSession):
    """Get file hash report from PostgreSQL - if not found, add to queue"""
    return await _get_or_queue_resource(db, "hash", file_hash, HashReport)


@app.post("/queue", response_model=QueueItemResponse)
async def add_to_queue(data: ResourceRequest, db: AsyncSession = Depends(get_db)):
    """Add resource to processing queue after checking for duplicates"""
    
    # Check if already in queue (not processed)
    stmt_queue = select(ResourceQueue).where(
        ResourceQueue.resource_type == data.resource_type,
        ResourceQueue.resource_value == data.value,
        ResourceQueue.processed == False
    )
    result_queue = await db.execute(stmt_queue)
    existing_queue_item = result_queue.scalar_one_or_none()
    
    if existing_queue_item:
        raise HTTPException(
            status_code=400, 
            detail=f"{data.resource_type.capitalize()} '{data.value}' already in processing queue with ID: {existing_queue_item.id}"
        )
    
    # Add to queue table if not found in main tables and not already in queue
    queue_item = ResourceQueue(
        resource_type=data.resource_type,
        resource_value=data.value
    )
    db.add(queue_item)
    await db.commit()
    await db.refresh(queue_item)
    
    return {
        "id": queue_item.id,
        "resource_type": queue_item.resource_type,
        "resource_value": queue_item.resource_value,
        "created_at": queue_item.created_at,
        "processed": queue_item.processed
    }




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