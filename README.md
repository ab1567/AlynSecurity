# AlyanaGlobal Device Guard – Phase 1

This repository contains the first phase of the **AlyanaGlobal Device Guard** project.  
The goal of Phase 1 is to deliver a working prototype that enforces a
domain allow‑list on Windows laptops and records attempts to access
blocked domains.  All files in this repository are production ready
templates that can be extended in subsequent phases.

## Structure

```
alyanaguard/
├── backend/         # FastAPI service for enrolment, policy and logs
│   ├── app/
│   │   ├── main.py           # Entry point for the API
│   │   ├── db.py             # Lightweight SQLite persistence layer
│   │   ├── models.py         # Pydantic request/response models
│   │   ├── auth.py           # Simple bearer token authentication
│   │   └── routers/
│   │       ├── __init__.py
│   │       ├── enroll.py     # `/enroll` endpoint
│   │       ├── policy.py     # `/policy` endpoint
│   │       └── logs.py       # `/logs` endpoint
│   └── requirements.txt      # Python dependencies
├── agent/           # Windows service written in C#
│   ├── src/
│   │   ├── AgentService.cs   # Windows Service bootstrap
│   │   ├── DnsProxy.cs       # Minimal DNS proxy skeleton
│   │   ├── PolicyClient.cs   # Fetches policy from the API
│   │   ├── Logger.cs         # Batches and posts blocked attempts
│   │   └── NetworkHardener.cs # Applies DNS/firewall settings
│   └── Agent.csproj          # .NET project file
└── deploy/
    └── nginx.conf     # Example Nginx reverse proxy configuration
```

### Backend

The backend is implemented using [FastAPI](https://fastapi.tiangolo.com/)
and stores data in a local SQLite database via SQLAlchemy.  It exposes
the following endpoints under `/api/v1`:

* **POST `/enroll`** – register a new device using an enrolment key.
  Pending devices must be manually approved via the admin interface
  before they receive a full policy.  The response includes a
  bearer token that the agent uses for subsequent requests.
* **GET `/policy`** – return the current allow‑list for an active
  device.  If the device is still pending approval the API returns
  a pending status instead of a policy.
* **POST `/logs`** – accept batches of blocked domain attempts.

Before running the backend you must install the Python dependencies:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload  # development mode
```

### Agent

The agent is a Windows Service written in C#.  It starts a DNS
listener on `127.0.0.1:53` and forwards allowed domains to
an upstream resolver.  Blocked domains return `NXDOMAIN`.  The agent
also applies system DNS settings to force Windows to use the local
proxy and installs firewall rules to prevent bypassing.  Blocked
attempts are queued and sent to the backend in batches.

The C# code in this repository is a skeleton; you will need the .NET
SDK to compile it.  To build the agent, run:

```bash
cd agent
dotnet build --configuration Release
```

### Deploy

An example `nginx.conf` is provided under the `deploy` directory.  It
demonstrates how to expose the FastAPI application via a reverse
proxy using SSL certificates for `alyanaglobal.com`.  Update the
certificate paths and server name as needed.

---

This repository sets the foundation for Phase 1 of the project.  Future
phases will extend the policy model, add application control and
tamper‑resistant features, and provide a comprehensive administrative
dashboard.