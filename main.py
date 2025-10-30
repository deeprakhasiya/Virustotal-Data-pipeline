import asyncio
import os
from dotenv import load_dotenv
import signal
import sys
from scheduler import scheduler
from database import init_db

load_dotenv()

async def main():
    """Main application entry point"""
    # Initialize database
    await init_db()
    print("Database initialized successfully!")
    
    # Start the scheduler
    scheduler.start_scheduler()
    print("VirusTotal Data Ingestion Service is running...")
    print("Press Ctrl+C to stop the service")
    
    # Keep the application running
    try:
        # Run forever
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        scheduler.stop_scheduler()
        sys.exit(0)

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}, shutting down...")
    scheduler.stop_scheduler()
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run the main application
    asyncio.run(main())