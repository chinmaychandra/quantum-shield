## Quantum Shield API Contract

This document defines the **stable contract** between:

- **Frontend** (`frontend/`) — Vite/React app
- **Middleware API** (`middleware/`) — FastAPI service
- **Backend worker** (`backend/`) — Celery worker and scanners

All examples assume the middleware is running at `http://localhost:8000`.

---

## Authentication

### POST `/auth/login`

**Description**: Authenticate a user and issue a JWT used by the frontend.

**Request (JSON)**:

```json
{
  "email": "user@example.com",
  "password": "string"
}
```

**Response 200 (JSON)**:

```json
{
  "access_token": "jwt-token-string",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "Alice",
    "roles": ["admin"]
  }
}
```

**Response 401 (JSON)**:

```json
{
  "detail": "Invalid credentials"
}
```

---

### POST `/auth/logout`

**Description**: Optional endpoint for revoking the current JWT.

**Headers**:

- `Authorization: Bearer <token>`

**Request body**: _empty_

**Response 204**: No content.

---

### GET `/auth/me`

**Description**: Returns the currently authenticated user (used by `authStore`).

**Headers**:

- `Authorization: Bearer <token>`

**Response 200 (JSON)**:

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "Alice",
  "roles": ["admin"]
}
```

---

## Scan Management (`/scan`)

### POST `/scan`

Used by `ScanForm` on the **NewScan** page to create a new scan.

**Headers**:

- `Authorization: Bearer <token>`

**Request (JSON)**:

```json
{
  "targets": ["example.com", "api.example.com"],
  "ports": [443],
  "include_subdomains": true,
  "tags": ["production"],
  "protocols": ["https"],
  "notes": "Quarterly crypto posture scan"
}
```

**Response 202 (JSON)**:

```json
{
  "scan_id": "uuid",
  "status": "queued",
  "created_at": "2026-03-06T12:00:00Z",
  "estimated_completion": "2026-03-06T12:05:00Z"
}
```

---

### GET `/scan/{scan_id}`

Used by **Dashboard** and **NewScan** to poll scan status.

**Response 200 (JSON)**:

```json
{
  "scan_id": "uuid",
  "status": "queued | running | completed | failed | cancelled",
  "progress": {
    "percent": 42,
    "discovered_targets": 10,
    "completed_targets": 4,
    "failed_targets": 1
  },
  "summary": {
    "total_endpoints": 25,
    "pqc_ready": 3,
    "needs_migration": 18,
    "legacy_only": 4
  },
  "started_at": "2026-03-06T12:01:00Z",
  "completed_at": null,
  "last_error": null
}
```

---

### GET `/scan/{scan_id}/events`

Optional HTTP long-poll endpoint for scan events (used as a fallback if WebSockets are unavailable).

**Query params**:

- `since_event_id` (optional, string)

**Response 200 (JSON)**:

```json
{
  "events": [
    {
      "id": "evt-1",
      "type": "scan_progress",
      "timestamp": "2026-03-06T12:01:10Z",
      "payload": {
        "scan_id": "uuid",
        "percent": 10
      }
    }
  ]
}
```

---

## Inventory & CBOM (`/inventory`)

### GET `/inventory/assets`

Used by **Inventory** page and `useInventory` hook to list all discovered assets.

**Query params** (all optional):

- `scan_id`: filter by originating scan
- `tag`: filter by tag
- `page`: integer, default 1
- `page_size`: integer, default 25

**Response 200 (JSON)**:

```json
{
  "items": [
    {
      "id": "asset-uuid",
      "hostname": "example.com",
      "ip": "203.0.113.10",
      "port": 443,
      "protocol": "https",
      "last_scanned_at": "2026-03-06T12:03:00Z",
      "pqc_label": "pqc-ready | needs-migration | legacy-only",
      "risk_score": 72
    }
  ],
  "page": 1,
  "page_size": 25,
  "total": 100
}
```

---

### GET `/inventory/assets/{asset_id}`

Detailed asset view backing the **AssetDrawer** component.

**Response 200 (JSON)**:

```json
{
  "id": "asset-uuid",
  "hostname": "example.com",
  "ip": "203.0.113.10",
  "port": 443,
  "protocol": "https",
  "scan_ids": ["scan-uuid"],
  "pqc_label": "needs-migration",
  "risk_score": 72,
  "tags": ["production"],
  "metadata": {
    "service": "web-frontend",
    "owner": "Payments team"
  }
}
```

---

### GET `/inventory/assets/{asset_id}/cbom`

Feeds the **CBOMTable** and `cbom.types.ts`.

**Response 200 (JSON)**:

```json
{
  "asset_id": "asset-uuid",
  "generated_at": "2026-03-06T12:03:30Z",
  "components": [
    {
      "category": "key_exchange",
      "algorithm": "X25519KYBER768",
      "tier": 2,
      "type": "hybrid",
      "safe": false,
      "evidence": {
        "tls_version": "TLS_1_3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384"
      }
    },
    {
      "category": "signature",
      "algorithm": "ML-DSA-65",
      "tier": 1,
      "type": "signature",
      "safe": true,
      "evidence": {
        "certificate_issuer": "Example PQC CA"
      }
    }
  ],
  "summary": {
    "highest_tier": 4,
    "pqc_components": 1,
    "legacy_components": 1,
    "broken_components": 0
  }
}
```

---

## Reports (`/reports`)

### GET `/reports/scans/{scan_id}`

High-level scan report for the **Dashboard** “view report” link.

**Response 200 (JSON)**:

```json
{
  "scan_id": "uuid",
  "generated_at": "2026-03-06T12:10:00Z",
  "summary": {
    "total_assets": 100,
    "pqc_ready": 5,
    "needs_migration": 70,
    "legacy_only": 25
  },
  "top_risks": [
    {
      "asset_id": "asset-uuid",
      "hostname": "legacy.example.com",
      "risk_score": 95,
      "primary_issue": "TLS_1_0 and RC4 in use"
    }
  ]
}
```

---

### GET `/reports/cbom/{asset_id}`

Returns a CBOM-centric report, used for exports and deep dives.

**Response 200 (JSON)**:

```json
{
  "asset_id": "asset-uuid",
  "hostname": "example.com",
  "cbom": {
    "components": [],
    "summary": {}
  },
  "recommendations": [
    {
      "id": "rec-1",
      "title": "Migrate to ML-KEM-768",
      "description": "Replace hybrid X25519KYBER768 with pure ML-KEM-768 for key exchange.",
      "priority": "high"
    }
  ]
}
```

---

### GET `/reports/export`

Export a scan-level or asset-level report in a specific format.

**Query params**:

- `scan_id` (optional)
- `asset_id` (optional)
- `format`: `"json" | "pdf" | "csv"` (default `"json"`)

**Response 200 (octet-stream or JSON)**:

- `format=json`: structured JSON report
- `format=pdf` or `csv`: binary stream with `Content-Disposition` set

---

## WebSocket Contract

### WebSocket endpoint: `ws://localhost:8000/ws/scans/{scan_id}`

Used by **LiveScanFeed** and `useScanStatus` for real-time updates.

#### Connection

- Client connects with `Authorization` header via query param:
  - `ws://localhost:8000/ws/scans/{scan_id}?token=<jwt>`

#### Outgoing server events

All messages are JSON objects with the following top-level shape:

```json
{
  "event": "string",
  "timestamp": "2026-03-06T12:01:00Z",
  "scan_id": "uuid",
  "payload": {}
}
```

##### Event: `scan_started`

```json
{
  "event": "scan_started",
  "timestamp": "2026-03-06T12:01:00Z",
  "scan_id": "uuid",
  "payload": {
    "targets": ["example.com"],
    "total_expected_assets": 50
  }
}
```

##### Event: `scan_progress`

Used to drive progress bars in **Dashboard** and **NewScan**.

```json
{
  "event": "scan_progress",
  "timestamp": "2026-03-06T12:01:10Z",
  "scan_id": "uuid",
  "payload": {
    "percent": 40,
    "discovered_targets": 15,
    "completed_targets": 6,
    "failed_targets": 1
  }
}
```

##### Event: `asset_discovered`

Feeds **Inventory** live updates.

```json
{
  "event": "asset_discovered",
  "timestamp": "2026-03-06T12:01:15Z",
  "scan_id": "uuid",
  "payload": {
    "asset": {
      "id": "asset-uuid",
      "hostname": "example.com",
      "ip": "203.0.113.10",
      "port": 443,
      "protocol": "https"
    }
  }
}
```

##### Event: `cbom_ready`

Used to refresh **CBOMTable** when a CBOM is generated.

```json
{
  "event": "cbom_ready",
  "timestamp": "2026-03-06T12:02:00Z",
  "scan_id": "uuid",
  "payload": {
    "asset_id": "asset-uuid"
  }
}
```

##### Event: `scan_completed`

```json
{
  "event": "scan_completed",
  "timestamp": "2026-03-06T12:05:00Z",
  "scan_id": "uuid",
  "payload": {
    "summary": {
      "total_assets": 100,
      "pqc_ready": 5,
      "needs_migration": 70,
      "legacy_only": 25
    }
  }
}
```

##### Event: `scan_failed`

```json
{
  "event": "scan_failed",
  "timestamp": "2026-03-06T12:02:00Z",
  "scan_id": "uuid",
  "payload": {
    "error": "Timeout connecting to target",
    "retryable": true
  }
}
```

---

## Backend <-> Middleware Contract (Jobs)

The middleware pushes jobs to the backend worker via a queue (e.g., Redis/Celery). At the contract level, a **scan job** has the following canonical structure:

```json
{
  "job_id": "uuid",
  "scan_id": "uuid",
  "targets": ["example.com"],
  "ports": [443],
  "options": {
    "include_subdomains": true,
    "protocols": ["https"]
  }
}
```

The backend is responsible for:

- Emitting progress events (`scan_progress`, `asset_discovered`, `cbom_ready`, `scan_completed`, `scan_failed`) back to the middleware, which then fans out via WebSocket.
- Persisting assets, scans, and CBOMs in Postgres according to the shapes defined above.

