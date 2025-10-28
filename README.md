#  VirusTotal Data Pipeline

A modern **FastAPI-based data pipeline** for querying and caching VirusTotal reports — built with **MongoDB** and **async Python** for high performance and scalability.

---

## ⚙️ Core Components

### **1. Database Layer (`database.py`)**
**Technology:** MongoDB 

- **Document-based storage** suits VirusTotal's nested JSON structure.
- **Schema flexibility** supports evolving threat intelligence data.

- **Compound index:** (`resource_id`, `resource_type`)  
  → Enables fast lookups for cached reports.

---

### **2. Data Management (`db_manager.py`)**
Handles data caching and database interaction.

- **Caching Strategy:** Simple “store and retrieve” without TTL (Time-To-Live)
- **Update Logic:** Uses **UPSERT** operations  
  → Updates if record exists, inserts if not
- **Data Preservation:** Stores the complete VirusTotal response  
  → Allows maximum flexibility for analytics or future enrichment

---

### **3. API Client (`vt_client.py`)**
Handles interaction with the **VirusTotal API**.


#### 🔹 Error Handling
- Graceful degradation if VirusTotal API is unavailable
- Retries can be added later with exponential backoff

#### 🔹 Supported Resources
- Domains  
- IP addresses  
- File hashes

---

### **4. Web Service (`main.py`)**
**Framework:** FastAPI — chosen for async performance and built-in documentation.


---

## ⚙️ Configuration

### **Environment Variables (.env)**
| Variable | Description | Example |
|-----------|--------------|----------|
| `MONGODB_URL` | MongoDB connection string | `mongodb+srv://<user>:<pass>@cluster.mongodb.net` |
| `DATABASE_NAME` | MongoDB database name | `Testdb` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | `your_api_key_here` |

---


## 🚀 Features

### ✅ **Current Implementation**
- **Multi-Resource Support:** Domains, IPs, and file hashes  
- **Intelligent Caching:** Database-level caching to minimize VirusTotal API calls  
- **RESTful API:** Clean and consistent endpoint structure  
- **Automatic Documentation:** Available via Swagger UI (`/docs`)  
- **Async Operations:** Non-blocking database and HTTP requests  

### 🌐 **Access API Documentation**
Once the app is running:
http://localhost:8000/docs


---
## 📡 API Endpoints

| **Method** | **Endpoint** | **Description** |
|-------------|--------------|-----------------|
| **GET** | `/` | Service health check |
| **GET** | `/report` | Get analysis report (uses cache) |
| **GET** | `/refresh` | Force refresh report (bypass cache) |
| **GET** | `/reports` | List all stored reports |

---


##  Current Limitations

### **1. Caching Strategy**
- ❌ No TTL (Time-to-Live) or auto-expiration  
- 🔁 Manual refresh required via `/refresh` endpoint  
- 📈 Storage may grow indefinitely (no cleanup mechanism yet)

### **2. Checkpoint Mechanism**
- Not implemented yet
- Justification:
  - Pipeline is **on-demand**, not continuous  
  - Each API request is **independent and idempotent**


---

## 💡 Possible Enhancements

| Enhancement | Description |
|--------------|--------------|
|  **TTL-based Caching** | Automatically expire stale data |
|  **Data Optimization** | Extract only relevant VirusTotal fields |
|  **Refresh Logic** | When the `/refresh` endpoint is called, delete existing domain/IP/hash data (if present) before fetching fresh data |
|**Retry Mechanism**| Retries can be added  with exponential backoff|


