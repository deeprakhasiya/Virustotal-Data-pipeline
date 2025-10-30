from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
from database import DomainReport, IPReport, HashReport
from sqlalchemy import select

class DBManager:
    def __init__(self):
        pass
    
    def _extract_analysis_stats(self, data: dict) -> tuple:
        """Extract analysis statistics from VirusTotal response"""
        malicious = suspicious = undetected = harmless = 0
        
        try:
            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                if 'last_analysis_stats' in attrs:
                    stats = attrs['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    undetected = stats.get('undetected', 0)
                    harmless = stats.get('harmless', 0)
        except (KeyError, TypeError, AttributeError) as e:
            print(f"Error extracting analysis stats: {e}")
        
        return malicious, suspicious, undetected, harmless
    
    async def store_domain_report(self, session: AsyncSession, domain: str, data: dict) -> Dict[str, Any]:
        """Store or update domain report in database"""
        malicious, suspicious, undetected, harmless = self._extract_analysis_stats(data)
        
        # Check if domain report already exists
        stmt = select(DomainReport).where(DomainReport.domain == domain).order_by(DomainReport.created_at.desc())
        result = await session.execute(stmt)
        existing_report = result.scalar_one_or_none()
        
        if existing_report:
            # Update existing report
            existing_report.malicious = malicious
            existing_report.suspicious = suspicious
            existing_report.undetected = undetected
            existing_report.harmless = harmless
            
            report = existing_report
            await session.commit()
            await session.refresh(report)
            print(f"✓ Updated existing domain report: {domain}")
        else:
            # Create new report
            report = DomainReport(
                domain=domain,
                malicious=malicious,
                suspicious=suspicious,
                undetected=undetected,
                harmless=harmless
            )
            session.add(report)
            await session.commit()
            await session.refresh(report)
            print(f"✓ Created new domain report: {domain}")
        
        return {
            "id": report.id,
            "resource_id": domain,
            "resource_type": "domain",
            "malicious": report.malicious,
            "suspicious": report.suspicious,
            "undetected": report.undetected,
            "harmless": report.harmless,
            "created_at": report.created_at
        }

    async def store_ip_report(self, session: AsyncSession, ip_address: str, data: dict) -> Dict[str, Any]:
        """Store or update IP report in database"""
        malicious, suspicious, undetected, harmless = self._extract_analysis_stats(data)
        
        # Check if IP report already exists
        stmt = select(IPReport).where(IPReport.ip_address == ip_address).order_by(IPReport.created_at.desc())
        result = await session.execute(stmt)
        existing_report = result.scalar_one_or_none()
        
        if existing_report:
            # Update existing report
            existing_report.malicious = malicious
            existing_report.suspicious = suspicious
            existing_report.undetected = undetected
            existing_report.harmless = harmless
            
            report = existing_report
            await session.commit()
            await session.refresh(report)
            print(f"✓ Updated existing IP report: {ip_address}")
        else:
            # Create new report
            report = IPReport(
                ip_address=ip_address,
                malicious=malicious,
                suspicious=suspicious,
                undetected=undetected,
                harmless=harmless
            )
            session.add(report)
            await session.commit()
            await session.refresh(report)
            print(f"✓ Created new IP report: {ip_address}")
        
        return {
            "id": report.id,
            "resource_id": ip_address,
            "resource_type": "ip",
            "malicious": report.malicious,
            "suspicious": report.suspicious,
            "undetected": report.undetected,
            "harmless": report.harmless,
            "created_at": report.created_at
        }

    async def store_hash_report(self, session: AsyncSession, file_hash: str, data: dict) -> Dict[str, Any]:
        """Store or update hash report in database"""
        malicious, suspicious, undetected, harmless = self._extract_analysis_stats(data)
        
        # Check if hash report already exists
        stmt = select(HashReport).where(HashReport.file_hash == file_hash).order_by(HashReport.created_at.desc())
        result = await session.execute(stmt)
        existing_report = result.scalar_one_or_none()
        
        if existing_report:
            # Update existing report
            existing_report.malicious = malicious
            existing_report.suspicious = suspicious
            existing_report.undetected = undetected
            existing_report.harmless = harmless
            
            report = existing_report
            await session.commit()
            await session.refresh(report)
            print(f"✓ Updated existing hash report: {file_hash}")
        else:
            # Create new report
            report = HashReport(
                file_hash=file_hash,
                malicious=malicious,
                suspicious=suspicious,
                undetected=undetected,
                harmless=harmless
            )
            session.add(report)
            await session.commit()
            await session.refresh(report)
            print(f"✓ Created new hash report: {file_hash}")
        
        return {
            "id": report.id,
            "resource_id": file_hash,
            "resource_type": "hash",
            "malicious": report.malicious,
            "suspicious": report.suspicious,
            "undetected": report.undetected,
            "harmless": report.harmless,
            "created_at": report.created_at
        }