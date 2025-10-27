from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING
import os
from dotenv import load_dotenv

load_dotenv()

class MongoDB:
    client: AsyncIOMotorClient = None
    database = None

mongodb = MongoDB()

async def connect_to_mongo():
    """Connect to MongoDB"""
    mongo_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    mongodb.client = AsyncIOMotorClient(mongo_url)
    mongodb.database = mongodb.client.Testdb
    
    # Create indexes
    await mongodb.database.reports.create_index([("resource_id", ASCENDING), ("resource_type", ASCENDING)])
    await mongodb.database.reports.create_index([("cache_until", ASCENDING)])
    await mongodb.database.checkpoints.create_index([("checkpoint_name", ASCENDING)])
    
    print("Connected to MongoDB successfully!")

async def close_mongo_connection():
    """Close MongoDB connection"""
    mongodb.client.close()

def get_database():
    return mongodb.database