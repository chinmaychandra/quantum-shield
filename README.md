## Quantum Shield

Quantum Shield is a hackathon project that scans your infrastructure for cryptographic posture, classifies endpoints by **post-quantum readiness**, and generates a **Cryptographic Bill of Materials (CBOM)** for each asset.

The stack is split into three pieces:

- `frontend/` — Vite/React + TypeScript UI
- `middleware/` — FastAPI service exposing HTTP + WebSocket APIs
- `backend/` — Celery-based worker that runs TLS scanners and PQC classification

All three parts share a strict contract described in `API_CONTRACT.md`.

---

## Project layout

- `frontend/`
  - `src/pages/` — top-level app pages (Login, Dashboard, NewScan, Inventory)
  - `src/components/` — reusable UI components (CBOM table, PQC badges, drawers)
  - `src/hooks/` — React hooks for scans and inventory
  - `src/api/` — API client abstraction
  - `src/store/` — auth store (Zustand)
  - `src/types/` — shared TS types (e.g., CBOM structures)
- `backend/`
  - `scanner/` — discovery, TLS scanner, cert parser, API prober
  - `classifier/` — PQC classifier, risk scorer, algorithm registry
  - `cbom/` — CBOM builder and label issuer
  - `tasks/` — Celery task entrypoints
  - `db/` — models and repository layer
  - `utils/` — logging and progress utilities
- `middleware/`
  - `routers/` — FastAPI routers (auth, scan, inventory, reports)
  - `services/` — auth, job dispatching, WebSocket manager
  - `schemas/` — Pydantic schemas for scan/CBOM
  - `middleware/` — auth and rate limiting middleware

---

## Environment setup

1. **Clone the repo**

   ```bash
   git clone <your-github-url> quantum-shield
   cd quantum-shield
   ```

2. **Create your `.env` file**

   ```bash
   cp .env.example .env
   ```

   Adjust credentials and secrets as needed.

3. **Python environment (backend + middleware)**

   ```bash
   cd backend
   python -m venv .venv
   .venv\Scripts\activate  # on Windows
   pip install -r requirements.txt
   cd ..\middleware
   pip install -r requirements.txt
   cd ..
   ```

4. **Node environment (frontend)**

   ```bash
   cd frontend
   npm install
   cd ..
   ```

---

## Running locally

1. **Start infrastructure + Python services with Docker Compose**

   From the project root:

   ```bash
   docker-compose up
   ```

   This will start:

   - Postgres (database)
   - Redis (message broker)
   - Backend Celery worker (scanner)
   - Middleware FastAPI app on `http://localhost:8000`

2. **Run the frontend dev server**

   In a separate terminal:

   ```bash
   cd frontend
   npm run dev
   ```

   The app will be available at `http://localhost:5173` (default Vite port).

3. **Login and try a scan**

   - Open the Login page, authenticate (implementation TBD).
   - Navigate to **New Scan**, submit targets.
   - Watch live progress on **Dashboard** and **Live Scan Feed**.
   - Inspect discovered assets and CBOMs on **Inventory**.

---

## Ownership

- **Daksh** — owner of `frontend/`
- **Shivang** — owner of `middleware/`
- **Chinmay** — owner of `backend/`


