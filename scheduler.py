import asyncio
import os
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from vt_client import VirusTotalClient
from db_manager import DBManager 
from database import  get_db, ResourceQueue

class VirusTotalScheduler:
    def __init__(self):
        self.vt_client = VirusTotalClient()
        self.db_manager = DBManager()
        self.scheduler = AsyncIOScheduler()
        
        # Cron expressions for processing queue
        self.queue_cron = os.getenv("QUEUE_CRON", "*/30 * * * * *")  # Every 30 seconds

    async def process_queue_items(self):
        """Process all unprocessed items from the queue"""
        print(f"[{datetime.now()}] Starting queue processing...")
        
        async for session in get_db():
            try:
                # Get all unprocessed items from queue
                stmt = select(ResourceQueue).where(
                    ResourceQueue.processed == False
                ).order_by(ResourceQueue.created_at.asc())  # Process oldest first
                
                result = await session.execute(stmt)
                queue_items = result.scalars().all()
                
                if not queue_items:
                    print("No items in queue to process")
                    return
                
                print(f"Found {len(queue_items)} items to process in queue")
                
                for queue_item in queue_items:
                    try:
                        print(f"Processing {queue_item.resource_type}: {queue_item.resource_value}")
                        
                        # Process based on resource type
                        if queue_item.resource_type == "domain":
                            vt_data = self.vt_client.get_domain_report(queue_item.resource_value)
                            if vt_data:
                                await self.db_manager.store_domain_report(session, queue_item.resource_value, vt_data)
                                print(f"✓ Processed domain: {queue_item.resource_value}")
                            else:
                                # Store null values if API call fails
                                await self.db_manager.store_domain_report(session, queue_item.resource_value, {})
                                print(f"✗ Failed to fetch domain: {queue_item.resource_value}")
                        
                        elif queue_item.resource_type == "ip":
                            vt_data = self.vt_client.get_ip_report(queue_item.resource_value)
                            if vt_data:
                                await self.db_manager.store_ip_report(session, queue_item.resource_value, vt_data)
                                print(f"✓ Processed IP: {queue_item.resource_value}")
                            else:
                                await self.db_manager.store_ip_report(session, queue_item.resource_value, {})
                                print(f"✗ Failed to fetch IP: {queue_item.resource_value}")
                        
                        elif queue_item.resource_type == "hash":
                            vt_data = self.vt_client.get_file_report(queue_item.resource_value)
                            if vt_data:
                                await self.db_manager.store_hash_report(session, queue_item.resource_value, vt_data)
                                print(f"✓ Processed hash: {queue_item.resource_value}")
                            else:
                                await self.db_manager.store_hash_report(session, queue_item.resource_value, {})
                                print(f"✗ Failed to fetch hash: {queue_item.resource_value}")
                        
                        # Mark as processed
                        queue_item.processed = True
                        queue_item.processed_at = datetime.now()
                        await session.commit()
                        print(f"✓ Marked as processed: {queue_item.resource_value}")
                        
                    except Exception as e:
                        print(f"Error processing queue item {queue_item.resource_value}: {e}")
                        # Continue with next item even if one fails
                        continue
                
                print(f"Queue processing completed. Processed {len(queue_items)} items.")
                
            except Exception as e:
                print(f"Error in queue processing: {e}")


    def start_scheduler(self):
        """Start the scheduled queue processing"""
        print("Starting VirusTotal Queue Processor...")
        print(f"Queue processing cron: {self.queue_cron}")
        
        # Schedule queue processing - choose one approach:
        
        # Approach 1: Process all queue items at once
        self.scheduler.add_job(
            self.process_queue_items,
            trigger=CronTrigger.from_crontab(self.queue_cron),
            id='queue_processing'
        )
        
        self.scheduler.start()
        print("Queue processor started successfully!")

    def stop_scheduler(self):
        """Stop the scheduler"""
        self.scheduler.shutdown()
        print("Scheduler stopped!")

# Global scheduler instance
scheduler = VirusTotalScheduler()