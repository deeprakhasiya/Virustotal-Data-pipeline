import requests
import time
from typing import Dict, Any, Optional
import os
from datetime import datetime, timedelta

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.last_request_time = 0
        self.rate_limit_delay = 15  # 4 requests/minute = 15 seconds between requests
    
    def _rate_limit(self):
        """Respect VirusTotal rate limits"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()
    
    def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain report from VirusTotal"""
        self._rate_limit()
        url = f"{self.base_url}/domains/{domain}"
        print(f"Fetching domain report for {domain} from VirusTotal")
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching domain report for {domain}: {e}")
            return None
    
    def get_ip_report(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get IP address report from VirusTotal"""
        self._rate_limit()
        url = f"{self.base_url}/ip_addresses/{ip}"
        print(f"Fetching IP report for {ip} from VirusTotal")
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching IP report for {ip}: {e}")
            return None
    
    def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get file hash report from VirusTotal"""
        self._rate_limit()
        url = f"{self.base_url}/files/{file_hash}"
        print(f"Fetching file report for {file_hash} from VirusTotal")
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching file report for {file_hash}: {e}")
            return None