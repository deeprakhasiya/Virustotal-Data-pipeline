from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
from bson import ObjectId
from pydantic import BaseModel, Field
from typing import Literal, Any

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


class ResourceRequest(BaseModel):
    resource_type: Literal["hash", "ip", "domain"]
    value: str = Field(..., description="The actual resource value, e.g., IP or hash string")
    
class VirusTotalReportBase(BaseModel):
    resource_id: str
    resource_type: str
    data: Dict[str, Any]


class VirusTotalReportResponse(VirusTotalReportBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    last_analysis_date: Optional[datetime] = None
    created_at: datetime
  
    class Config:
        from_attributes = True
        populate_by_name = True
        json_encoders = {ObjectId: str}



