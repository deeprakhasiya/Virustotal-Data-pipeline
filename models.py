from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()


class VirusTotalReport(Base):
    __tablename__ = "virustotal_reports"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    resource_id = Column(String, nullable=False, index=True)  # domain, IP, or hash
    resource_type = Column(String, nullable=False)  # 'domain', 'ip', 'hash'
    data = Column(JSON, nullable=False)  # Full VirusTotal response
    created_at = Column(DateTime, default=func.now())

