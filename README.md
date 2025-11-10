

#  VirusTotal Data Pipeline  

A **modern asynchronous data pipeline** built with **FastAPI**, **PostgreSQL**, and **APScheduler** to automatically fetch, and refresh **VirusTotal reports** for domains, IPs, and file hashes.  

---

##  Core Architecture

| Component | Purpose | 
|------------|----------|
| **API Layer (`server.py`)** | Handles  API endpoints using FastAPI | 
| **Database Layer (`database.py`)** | Manages PostgreSQL tables for reports and queue | 
| **Data Manager (`db_manager.py`)** | Performs UPSERT operations (insert/update) for reports | 
| **Scheduler (`scheduler.py`)** | Periodically processes unprocessed items in queue | 
| **Entry Point (`main.py`)** | Initializes database and starts background scheduler | 
| **Schemas (`schemas.py`)** | Defines request/response data models |

---

##  What This Pipeline Does  

1. **Accepts VirusTotal resource requests (domain/IP/hash)** via FAST API.  
2. **Checks the local PostgreSQL database** for  results.  
3. If not found → **adds the item to a processing queue** (`resource_queue` table).  
4. **Scheduler (`scheduler.py`)** periodically picks unprocessed queue items and calls the **VirusTotal API**.  
5. **Results are parsed and stored** into structured tables (`domain_reports`, `ip_reports`, `hash_reports`).  
6. Clients can later fetch cached data instantly from the API.  

---

##  Database Design

| Table | Description |
|--------|--------------|
| **domain_reports** | Stores VirusTotal stats for domains |
| **ip_reports** | Stores VirusTotal stats for IP addresses |
| **hash_reports** | Stores VirusTotal stats for file hashes |
| **resource_queue** | Stores pending VirusTotal resources waiting for background processing |

### ✅ Common Fields
- `id`: UUID primary key  
- `malicious`, `suspicious`, `undetected`, `harmless`: Counts from VirusTotal  
- `created_at`: Timestamp when record was created  

---

##  Scheduler (Automated Background Processing)

### 🔹 Purpose
The scheduler continuously monitors the **`resource_queue`** table and fetches VirusTotal data for any **unprocessed** resources.

### 🔹 How It Works
1. Runs every **1 minute** (configurable via `.env` variable `QUEUE_CRON`).  
2. Fetches all `processed == False` items from queue.  
3. Calls the appropriate VirusTotal API (domain/IP/hash).  
4. Stores the results in PostgreSQL via `DBManager`.  
5. Marks each queue item as **processed**.

### 🔹 Cron Expression
```bash
QUEUE_CRON=*/30 * * * * *   # every 30 seconds
```

You can change this to run every 5 minutes:
```bash
QUEUE_CRON=*/5 * * * *      # every 5 minutes
```

---

## ⚙️ Environment Configuration (.env)

| Variable | Description | Example |
|-----------|--------------|----------|
| `DATABASE_URL` | PostgreSQL async connection string | `postgresql+asyncpg://username:password@localhost/virustotal_db` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | `your_api_key_here` |
| `QUEUE_CRON` | Cron schedule for scheduler job | `*/30 * * * * *` |

---

## 🚀 How to Run

### **1️⃣ Clone the Repo**
```bash
git clone https://github.com/<your-username>/virustotal-data-pipeline.git
cd virustotal-data-pipeline
```

### **2️⃣ Setup Environment**
```bash
python -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file:
```bash
DATABASE_URL=postgresql+asyncpg://postgres:1234@localhost/virustotal_db
VIRUSTOTAL_API_KEY=your_api_key
QUEUE_CRON=*/30 * * * * *
```

### **3️⃣ Initialize Database**
```bash
python main.py
```
This:
- Creates all tables
- Starts the background scheduler that processes queued VirusTotal resources  

---

##  API Endpoints

| Method | Endpoint | Description |
|---------|-----------|-------------|
| **GET** | `/` | Health check |
| **GET** | `/report` | Get  report (or queue if not found) |
| **POST** | `/queue` | Manually add resource to processing queue |
| **GET** | `/refresh` | Force refresh and fetch from VirusTotal |
| **GET** | `/reports` | Get all stored reports (paginated) |

### Example Request
```json
{
  "resource_type": "domain",
  "value": "example.com"
}
```

---

##  Data Flow Summary

```
           ┌────────────┐
           │  Client    │
           └──────┬─────┘
                  │  (API Request)
                  ▼
           ┌────────────┐
           │ FastAPI     │──▶ Check DB
           └────────────┘
                  │
      ┌───────────┴───────────┐
      ▼                       ▼
 [Found in DB]         [Not Found]
   Return report     Add to Resource Queue
                          │
                          ▼
                  ┌────────────────┐
                  │ APScheduler Job│
                  │(Every 60 sec)  │
                  └──────┬─────────┘
                         ▼
               Fetch VirusTotal API
                         │
                         ▼
                  Store in PostgreSQL
```

---

##  Possible Future Enhancements

| Feature | Description |
|----------|--------------|
| **TTL-based caching** | Auto-expire old data |
| **Retry mechanism** | Exponential backoff for API failures |
| **Web UI** | Admin panel for monitoring reports and queue |

---

##  Why This Design Works

✅ **Async-first design** — handles I/O (DB & API) concurrently  
✅ **Resilient** — uses queue-based recovery for failed/missing data  
✅ **Developer-friendly** — automatic docs & strong typing  

