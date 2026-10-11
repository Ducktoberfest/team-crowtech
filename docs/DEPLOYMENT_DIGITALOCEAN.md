# DigitalOcean App Platform Deployment Guide for Veyra

This guide covers deploying **Veyra** (FastAPI backend, cybersecurity dashboard, and open-weight model defense layer) to **DigitalOcean App Platform** using Docker.

---

## 1. Architecture Overview

```
                                    +-----------------------------------+
                                    | DigitalOcean App Platform (Web)   |
  Untrusted Prompt / User Request   | - Port: $PORT (Dynamic)           |
  ================================> | - Docker: python:3.12-slim        |
                                    | - FastAPI + Static Dashboard      |
                                    | - Health check: /health           |
                                    +-----------------+-----------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
         +-------------------------------+                         +-------------------------------+
         | Persistence Layer             |                         | Open-Weight AI Model Host     |
         | Option A: Persistent Volume   |                         | Option A: Droplet with Ollama |
         |   (/app/data/veyra.db)        |                         |   (Private VPC network)       |
         | Option B: Managed PostgreSQL  |                         | Option B: Remote Cloud API    |
         +-------------------------------+                         +-------------------------------+
```

---

## 2. Prerequisites

1. A [DigitalOcean Account](https://cloud.digitalocean.com).
2. GitHub repository containing the Veyra codebase.
3. An active Ollama instance (either on a DigitalOcean Droplet, a GPU Droplet, or hosted cloud endpoint).

---

## 3. Step-by-Step App Platform Deployment

### Step 1: Create a New App in DigitalOcean Console

1. Log in to the [DigitalOcean Control Panel](https://cloud.digitalocean.com/apps).
2. Click **Create** -> **Apps**.
3. Under **Service Provider**, choose **GitHub**.
4. Select your repository (e.g. `team-crowtech`) and branch (`main`).
5. Select **Autodeploy** if you want new git commits automatically deployed.

### Step 2: Configure Build & Container Settings

App Platform will detect the `Dockerfile` at the root of the repository:
- **Source Directory:** `/` (root)
- **Dockerfile Path:** `Dockerfile`
- **HTTP Port:** DigitalOcean injects `$PORT` into the container environment. The Dockerfile's CMD automatically binds to `${PORT:-8000}`.
- **HTTP Request Routes:** Set route to `/`.

### Step 3: Configure Environment Variables

Under the App's **Settings** -> **Components** -> **Environment Variables**, configure:

| Variable | Recommended Production Value | Description |
| :--- | :--- | :--- |
| `OLLAMA_BASE_URL` | `http://<droplet-vpc-ip>:11434` or public HTTPS URL | Endpoint for open-weight model |
| `OLLAMA_MODEL` | `gemma2:9b` | Model name (e.g., Gemma 2, Gemma 4) |
| `OLLAMA_API_KEY` | *(Set as Encrypted Secret)* | Bearer token if using authenticated gateway |
| `OLLAMA_TIMEOUT_SECONDS` | `15.0` | Timeout threshold for inference calls |
| `VEYRA_DEMO_MODE` | `false` | Set `false` for live inference (`true` for offline mock) |
| `FAIL_CLOSED_ON_ERROR` | `true` | Conservative posture: quarantine on failure |
| `RISK_THRESHOLD_BLOCK` | `0.70` | Score threshold for BLOCK |
| `RISK_THRESHOLD_QUARANTINE` | `0.35` | Score threshold for QUARANTINE |
| `DATABASE_PATH` | `/app/data/veyra.db` | SQLite database file location |
| `STORE_RAW_PROMPTS` | `false` | Privacy gate: omit raw prompts from audit log |
| `ALLOWED_ORIGINS` | `https://<your-app-name>.ondigitalocean.app` | Restrictive CORS setting |
| `RATE_LIMIT_PER_MINUTE`| `60` | Client rate limit per IP |

> **Security Directives:**
> - Never hardcode API keys or credentials in `.env` files committed to Git.
> - Mark sensitive keys (like `OLLAMA_API_KEY`) as **Type: Secret (Encrypted)** in DigitalOcean App Platform.

### Step 4: Configure Health Check

In DigitalOcean App Platform component settings:
- **Health Check Path:** `/health`
- **Initial Delay:** `10 seconds`
- **Period:** `30 seconds`
- **Failure Threshold:** `3`

The `/health` endpoint checks database connectivity and operational status without disclosing sensitive credentials.

---

## 4. Persistent Storage on DigitalOcean

> [!IMPORTANT]
> **Ephemeral Filesystem Note:** By default, App Platform containers are stateless and ephemeral. If a container restarts or a new deployment is pushed, local files inside the container are replaced.

To persist your audit logs, analysis history, and telemetry:

### Option A: App Platform Persistent Volume (Recommended for SQLite)
1. In the App Platform Dashboard, navigate to your service component.
2. Under **Storage**, click **Add Volume**.
3. Set the Mount Path to `/app/data`.
4. Choose volume size (e.g., 5 GB or 10 GB).
5. Ensure `DATABASE_PATH=/app/data/veyra.db` is set in environment variables.

### Option B: Managed PostgreSQL (Recommended for Distributed Clusters)
For multi-instance horizontal scaling, attach a **DigitalOcean Managed Database**:
1. Click **Create** -> **Databases** -> **PostgreSQL**.
2. Under your app settings, add the database component as a dependency.
3. DigitalOcean automatically injects `DATABASE_URL`.

---

## 5. Hosting the Open-Weight AI Model (Ollama on DigitalOcean)

To run the open-weight model (such as Google Gemma 2 / 9B) on DigitalOcean:

### Setup on a DigitalOcean Droplet:
1. Launch an Ubuntu 22.04 or 24.04 Droplet (Memory-Optimized or GPU Droplet recommended for fast inference).
2. SSH into the Droplet:
   ```bash
   ssh root@<droplet-ip>
   ```
3. Install Ollama:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```
4. Pull the target open-weight model:
   ```bash
   ollama pull gemma2:9b
   ```
5. Configure Ollama to listen on the private VPC interface:
   ```bash
   # In /etc/systemd/system/ollama.service.d/environment.conf
   [Service]
   Environment="OLLAMA_HOST=0.0.0.0:11434"
   ```
   Restart Ollama:
   ```bash
   sudo systemctl daemon-reload && sudo systemctl restart ollama
   ```
6. In App Platform, set `OLLAMA_BASE_URL=http://<droplet-private-vpc-ip>:11434`.

---

## 6. Verification & Troubleshooting

Once deployed, verify:
1. Health check:
   ```bash
   curl https://<your-app>.ondigitalocean.app/health
   ```
   Expected response:
   ```json
   {"status":"healthy","database":"connected","model_configured":"gemma2:9b","version":"1.0.0"}
   ```
2. Interactive Dashboard:
   Open `https://<your-app>.ondigitalocean.app` in any modern browser.
3. Audit Log Persistence:
   Submit an analysis via the dashboard, trigger an app redeploy, and confirm that the audit record still appears in History.
