from datetime import datetime, timedelta
from database import get_database
from typing import Optional, Dict, Any
from bson import ObjectId

class DBManager:
    def __init__(self):
        pass
    
    
    async def get_cached_report(self, resource_id: str, resource_type: str) -> Optional[Dict[str, Any]]:
        """Get cached report if it exists and is still valid"""
        db = get_database()
        
        report = await db.reports.find_one({
            "resource_id": resource_id,
            "resource_type": resource_type,
         
        })
        
        return report
    
    async def store_report(self, resource_id: str, resource_type: str, data: dict) -> Dict[str, Any]:
        """Store report in database with cache expiration"""
        db = get_database()
        
        
        # Extract last_analysis_date from data if available
        last_analysis_date = None
        if 'data' in data and 'attributes' in data['data']:
            attrs = data['data']['attributes']
            if 'last_analysis_date' in attrs:
                last_analysis_date = datetime.fromtimestamp(attrs['last_analysis_date'])
        
        current_time = datetime.now()
        
        # Use upsert to update or insert
        report_data = {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "data": data,
            "created_at": current_time,
        }
        
        result = await db.reports.update_one(
            {
                "resource_id": resource_id,
                "resource_type": resource_type
            },
            {"$set": report_data},
            upsert=True
        )
        
        # Return the updated/inserted document
        if result.upserted_id:
            report_data["_id"] = result.upserted_id
        else:
            # For update, fetch the updated document
            report_data = await db.reports.find_one({
                "resource_id": resource_id,
                "resource_type": resource_type
            })
        
        return report_data