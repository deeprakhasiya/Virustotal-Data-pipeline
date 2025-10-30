import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, DateTime, Integer ,Boolean
from sqlalchemy.sql import func
import uuid

load_dotenv()

Base = declarative_base()

# Domain Reports Table
class DomainReport(Base):
    __tablename__ = "domain_reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, index=True)
    malicious = Column(Integer, default=0)
    suspicious = Column(Integer, default=0)
    undetected = Column(Integer, default=0)
    harmless = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())

# IP Reports Table
class IPReport(Base):
    __tablename__ = "ip_reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address = Column(String(45), nullable=False, index=True)
    malicious = Column(Integer, default=0)
    suspicious = Column(Integer, default=0)
    undetected = Column(Integer, default=0)
    harmless = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())

# Hash Reports Table
class HashReport(Base):
    __tablename__ = "hash_reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_hash = Column(String(64), nullable=False, index=True)
    malicious = Column(Integer, default=0)
    suspicious = Column(Integer, default=0)
    undetected = Column(Integer, default=0)
    harmless = Column(Integer, default=0)
    created_at = Column(DateTime, default=func.now())

# Resource Queue Table
class ResourceQueue(Base):
    __tablename__ = "resource_queue"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    resource_type = Column(String(10), nullable=False)  # 'domain', 'ip', 'hash'
    resource_value = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    processed = Column(Boolean, default=False)

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://username:password@localhost/virustotal_db")

engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables created successfully!")

async def get_db():
    """Get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()