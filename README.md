# Sentinel-X

Sentinel-X is a human-in-the-loop investigation workspace MVP. It is for analysis of evidence an investigator explicitly uploads or imports; it does not browse, scrape, message, contact, or act on any platform or person. Findings are advisory and require investigator confirmation. Age estimation is out of scope.

## Current features

The app provides a FastAPI API with JWT authentication and Investigator, Reviewer, and Admin roles; case create/read/update endpoints; evidence upload tied to cases; SHA-256 hashing; private local file storage; and a hash-chained audit trail with append-only database triggers. The React/Vite workbench includes case management, an evidence lab, explicit analysis controls, a Chart.js fusion history, a Cytoscape correlation map, a reviewer queue, and downloadable evidence reports.

The upload path accepts PNG, JPEG, WebP, WAV, MP3, and JSON files up to 15 MiB, validates file signatures/formats, and requires an explicit attestation that uploads are synthetic or harmless benign test data. Files are stored outside the public web directory and are served only as authenticated downloads. The attestation is not a content classifier; use fabricated benign files only.

The local analysis modules calculate image metadata and perceptual hashes, compare duplicate candidates, run opt-in local Tesseract OCR when configured, identify a small set of transparent language-pattern prompts in uploaded JSON messages, and extract candidate usernames, URLs, invite links, and wallet-like strings from that file only. Behavioral summaries are limited to the uploaded messages. Audio transcription is not configured. The local hash-list interface contains only a dummy benign fixture. The fusion score is an explainable review-priority aid—not a person or content classification. No signal triggers a report, contact, referral, or other action. Human review is explicit.

The correlation graph shows entities extracted from uploaded synthetic JSON exports and the cases where they appeared. Edges start as “possible”; a human can mark a relationship “confirmed.” The reviewer queue allows Confirm, Reject, or Escalate and records the choice in the audit chain. PDF reports contain evidence metadata and hashes, signal summaries, score explanations, graph-link counts, and reviewer decisions; original files are not embedded.

The default developer setup uses SQLite and a local relational graph projection. Docker Compose provides PostgreSQL for case/evidence/audit records and Neo4j for the correlation graph. The graph driver is enabled when `NEO4J_URI` is configured; otherwise the same graph API is served from relational records. Alembic migrations run at API startup. New evidence files are encrypted at rest with Fernet authenticated encryption; the original SHA-256 is retained for custody and verification.

## Run the complete stack with Docker Compose

Install Docker Desktop, then from the project root:

```powershell
Copy-Item .env.example .env
# Replace the demo passwords/JWT secret and EVIDENCE_ENCRYPTION_KEY with generated values.
docker compose up --build
```

Open <http://localhost:8080>. Stop the stack with `docker compose down`; named database and evidence volumes are retained. To delete the synthetic demo state and uploaded files, use `docker compose down -v` (this removes all Compose-managed database and evidence volumes). The PostgreSQL and Neo4j ports are bound to loopback only. Neo4j Browser is at <http://localhost:7474>. Seed the generated benign fixtures after startup:

```powershell
docker compose exec api python seed_synthetic.py
```

For running services, the API health endpoint is <http://localhost:8080/api/v1/health>; interactive API documentation is at <http://localhost:8080/docs>.

## Run locally

### API

```powershell
cd api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
# Put a generated Fernet key in the project-root .env file, then:
uvicorn app.main:app --reload --env-file ..\.env
```

API docs: <http://127.0.0.1:8000/docs>

### Web

```powershell
cd web
npm install
npm run dev
```

Open the URL printed by Vite. The development server proxies `/api` to `http://127.0.0.1:8000`.

## Synthetic demo users

The API creates these local accounts if missing:

| Role | Username | Password |
| --- | --- | --- |
| Investigator | `investigator_alice` | `Password123!` |
| Reviewer | `reviewer_riley` | `Password123!` |
| Admin | `admin_avery` | `Password123!` |

These are demo credentials only. Do not deploy with them. Set a unique `JWT_SECRET` and configure a production database before any deployment.

The example `.env` values are also demo-only. The seed script initializes demo users for local synthetic-data testing. Generate a Fernet key with:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store the key in a secret manager or protected environment file and back it up separately from the evidence volume. Losing the key makes encrypted evidence permanently unreadable; changing it without decrypting and re-encrypting all files has the same effect. New evidence uploads fail with HTTP 503 if encryption is missing or invalid. Existing plaintext files remain readable for compatibility until explicitly migrated. To encrypt existing database-backed files after setting the key:

```powershell
cd api
python encrypt_legacy_evidence.py
```

The migration script verifies each plaintext file against its recorded SHA-256 before encryption and appends an audit record. Back up the database, evidence directory, and encryption key before running it.

## Tests

```powershell
cd api
python -m pytest -q
```

The test suite uses isolated in-memory SQLite and synthetic case data.

## Seed synthetic demo data

```powershell
cd api
python seed_synthetic.py
```

The script idempotently creates three fabricated cases, JSON chat fixtures, and a generated abstract image. Names and reserved `.invalid` URLs are dummy values. No platform is contacted.

## Evidence API

- `POST /api/v1/cases/{case_id}/evidence` — authenticated Investigator/Admin upload; multipart fields `file` and `synthetic_data_confirmed=true`.
- `GET /api/v1/cases/{case_id}/evidence` — list case evidence metadata and hashes.
- `GET /api/v1/evidence/{evidence_id}/download` — authenticated, audited download as an attachment.
- `POST /api/v1/cases/{case_id}/evidence/{evidence_id}/analyze` — explicitly run local analysis on an uploaded file.
- `POST /api/v1/cases/{case_id}/fusion` — create a documented human-review priority assessment.
- `GET /api/v1/graph` — read the local case/entity graph; `POST /api/v1/graph/links/{link_id}/confirm` records a human confirmation.
- `GET /api/v1/review-queue` and `POST /api/v1/review-queue/{assessment_id}/decision` — reviewer queue and human decision.
- `GET /api/v1/cases/{case_id}/report.pdf` — generate and audit a PDF case report.

Set `EVIDENCE_DIR` to a private persistent directory when running outside local development. Keep the encryption key stable and backed up. The initial Alembic revision adopts databases created by the earlier `create_all` startup without dropping tables; later schema changes should be added as new forward migrations.

### Optional local OCR

The API uses the `pytesseract` wrapper. To enable OCR, install the Tesseract executable separately and make it available on `PATH`; otherwise image analysis explicitly reports OCR as unavailable. Voice transcription is not included/configured and does not infer speaker attributes.

## Audit trail limitations

Hash chaining detects altered entries and broken interior links, and SQLite triggers reject ordinary updates/deletes. A database administrator able to replace the database can still truncate the newest tail or rewrite the database and triggers. The chain is tamper-evident, not independently immutable; later production work should anchor periodic hashes outside the database and use controlled database access.

## Data safety

Use only fabricated, benign test data. Never upload real abuse material or real-person data to this MVP. The synthetic-data checkbox is an attestation, not an automated content-safety scan. No platform integrations, collection, or age estimation are implemented. Visual analysis is limited to image dimensions/mode, hashing, duplicate detection, and optional OCR; it will not infer age, identify faces, or label people. Pattern rules are deterministic examples, not a validated NLP model; no transformer classifier is bundled.
