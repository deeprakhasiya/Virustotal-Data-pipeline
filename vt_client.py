import aiohttp
import asyncio
from typing import Dict, Any, Optional
import os

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.last_request_time = 0
        self.rate_limit_delay = 15
        self._session = None

    async def get_session(self):
        """Get or create aiohttp session"""
        if self._session is None:
            self._session = aiohttp.ClientSession(headers=self.headers)
        return self._session

    async def _rate_limit(self):
        """Async rate limiting"""
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
            
        self.last_request_time = asyncio.get_event_loop().time()

    async def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Async domain report from VirusTotal"""
        await self._rate_limit()
        url = f"{self.base_url}/domains/{domain}"
        print(f"Fetching domain report for {domain} from VirusTotal")
        
        try:
            session = await self.get_session()
            async with session.get(url, timeout=30) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            print(f"Error fetching domain report for {domain}: {e}")
            return None

    async def get_ip_report(self, ip: str) -> Optional[Dict[str, Any]]:
        """Async IP address report from VirusTotal"""
        await self._rate_limit()
        url = f"{self.base_url}/ip_addresses/{ip}"
        print(f"Fetching IP report for {ip} from VirusTotal")
        
        try:
            session = await self.get_session()
            async with session.get(url, timeout=30) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            print(f"Error fetching IP report for {ip}: {e}")
            return None

    async def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Async file hash report from VirusTotal"""
        await self._rate_limit()
        url = f"{self.base_url}/files/{file_hash}"
        print(f"Fetching file report for {file_hash} from VirusTotal")
        
        try:
            session = await self.get_session()
            async with session.get(url, timeout=30) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            print(f"Error fetching file report for {file_hash}: {e}")
            return None

    async def close(self):
        """Close the aiohttp session"""
        if self._session:
            await self._session.close()