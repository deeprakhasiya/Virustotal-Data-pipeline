from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Literal

class ResourceRequest(BaseModel):
    resource_type: Literal["hash", "ip", "domain"]
    value: str = Field(..., description="The actual resource value, e.g., IP or hash string")

class VirusTotalReportBase(BaseModel):
    resource_id: str
    resource_type: str
    malicious: Optional[int] = 0
    suspicious: Optional[int] = 0
    undetected: Optional[int] = 0
    harmless: Optional[int] = 0

class VirusTotalReportResponse(VirusTotalReportBase):
    id: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class ReportsListResponse(BaseModel):
    domains: List[VirusTotalReportResponse]
    ips: List[VirusTotalReportResponse]
    hashes: List[VirusTotalReportResponse]

class StatsResponse(BaseModel):
    total_domains: int
    total_ips: int
    total_hashes: int
    malicious_count: int

class QueueItemResponse(BaseModel):
    id: str
    resource_type: str
    resource_value: str
    created_at: datetime
    processed: bool
    
    class Config:
        from_attributes = True
