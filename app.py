from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Iterator

from authlib.integrations.flask_client import OAuth
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, abort, jsonify, redirect, request, send_file, session, url_for
import qrcode
from qrcode.image.svg import SvgPathImage
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
EVIDENCE_DIR = Path(os.environ.get("ESENSE_EVIDENCE_PATH", DATA_DIR / "evidence"))
DB_PATH = Path(os.environ.get("ESENSE_DB_PATH", DATA_DIR / "esense.db"))
POLICY_PATH = BASE_DIR / "policy" / "electro_ekom.v0.1.json"
MAX_JSON_BYTES = 400_000
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024
ALLOWED_EVIDENCE_EXTENSIONS = {
    ".pdf", ".jpg", ".jpeg", ".png", ".webp", ".txt", ".csv",
    ".xlsx", ".xls", ".docx", ".odt", ".zip",
}
DEMO_ASSIGNMENT_TITLE = "FieldSeal demo: Level 2 EV charger installation"
DEMO_REPORT_LANGUAGES = {"no", "en", "pl", "lt", "lv"}
DEMO_ACCESS_PRESETS = {
    "owner": {
        "duration_days": None,
        "duration_kind": "persistent",
        "purpose": "Operation, maintenance, insurance and future alterations",
    },
    "contractor": {
        "duration_days": 30,
        "duration_kind": "time_limited",
        "purpose": "Planning an approved alteration to the existing installation",
    },
    "authority": {
        "duration_days": 7,
        "duration_kind": "case_limited",
        "purpose": "Inspection under a valid legal basis",
    },
}
DEMO_PUBLIC_REPORT = {
    "title": "Issued EV charger installation report",
    "subtitle": "Synthetic US residential case: hardwired 48 A Level 2 EV charger",
    "job_reference": "FS-EV-DEMO-2026-0717-01",
    "property_reference": "Synthetic residence / garage and service panel MSP-1, Bradenton, Florida",
    "work_period": {"started": "17 Jul 2026, 08:30", "completed": "17 Jul 2026, 16:10"},
    "parties": [
        {"label": "Property owner", "value": "Demo homeowner (synthetic)"},
        {"label": "Contractor", "value": "Suncoast EV Electric LLC (synthetic)"},
        {"label": "Responsible contractor", "value": "Florida-licensed electrical contractor (synthetic)"},
    ],
    "summary": (
        "A hardwired 48 A Level 2 EV charger was installed in a synthetic residential garage on a dedicated "
        "60 A, 240 V branch circuit. The package records the load calculation, permit placeholder, equipment "
        "installation, electrical tests, commissioning, photographs and controlled owner handover."
    ),
    "work_items": [
        "Documented service and load calculation for the added continuous EV charging load",
        "Installed a dedicated 60 A, 240 V branch circuit from service panel MSP-1",
        "Mounted and hardwired a 48 A Level 2 EV charger in the garage",
        "Applied circuit and disconnect labels and recorded commissioning evidence",
    ],
    "tests_and_results": [
        {"test": "Equipment grounding conductor continuity", "result": "0.12 ohm", "status": "Pass"},
        {"test": "Insulation resistance", "result": ">500 MOhm", "status": "Pass"},
        {"test": "Supply voltage and polarity", "result": "241 V / correct", "status": "Pass"},
        {"test": "Termination torque verification", "result": "Per manufacturer", "status": "Pass"},
        {"test": "EV charger commissioning and fault test", "result": "PASS", "status": "Pass"},
    ],
    "documents": [
        {"name": "Load calculation", "detail": "Synthetic service and continuous-load calculation", "status": "Included"},
        {"name": "Permit and inspection record", "detail": "Synthetic permit placeholder and review status", "status": "Included"},
        {"name": "Panel schedule", "detail": "MSP-1 updated with EV charger circuit identification", "status": "Included"},
        {"name": "Product and owner data", "detail": "Breaker, conductor and EV charger documentation", "status": "Included"},
        {"name": "Commissioning record", "detail": "Electrical checks and EV charger functional test", "status": "Included"},
        {"name": "Photographic record", "detail": "Panel, route, labels and completed charger", "status": "Included"},
    ],
    "timeline": [
        {"time": "17 Jul, 08:30", "event": "Assignment accepted and responsibility recorded"},
        {"time": "17 Jul, 09:05", "event": "Load calculation and installation plan approved"},
        {"time": "17 Jul, 15:25", "event": "Electrical tests and charger commissioning added"},
        {"time": "17 Jul, 16:10", "event": "Version 1 issued to the property owner"},
    ],
    "deviations": "No deviations were registered in this synthetic exercise.",
    "handover_notes": (
        "The property owner retains the complete issued package. A future contractor or competent authority "
        "may receive purpose-limited access without making the report or personal data public."
    ),
}


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env(BASE_DIR / ".env")
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
)

RECEIPT_SECRET: <REDACTED>
DOCUMENT_SECRET: <REDACTED>
DOCUMENT_KEY = hashlib.sha256(b"esense-document-encryption-v1:" + str(DOCUMENT_SECRET).encode("utf-8")).digest()
MIDNIGHT_ENABLED = os.environ.get("ESENSE_MIDNIGHT_ENABLED", "").strip().lower() in {"1", "true", "yes"}
MIDNIGHT_NETWORK = os.environ.get("ESENSE_MIDNIGHT_NETWORK", "preprod").strip() or "preprod"
MIDNIGHT_CONTRACT_ADDRESS = os.environ.get("ESENSE_MIDNIGHT_CONTRACT_ADDRESS", "").strip()
MIDNIGHT_WORKER_TOKEN: <REDACTED>
MIDNIGHT_READY = bool(
    MIDNIGHT_ENABLED
    and MIDNIGHT_CONTRACT_ADDRESS
    and MIDNIGHT_WORKER_TOKEN
)

oauth = OAuth(app)
google_enabled = bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))
if google_enabled:
    oauth.register(
        name="google",
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret: <REDACTED>
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

microsoft_tenant_id = os.environ.get("MICROSOFT_TENANT_ID", "").strip()
microsoft_allowed_domains = {
    value.strip().lower()
    for value in os.environ.get("MICROSOFT_ALLOWED_DOMAINS", "").split(",")
    if value.strip()
}
microsoft_enabled = bool(
    microsoft_tenant_id
    and os.environ.get("MICROSOFT_CLIENT_ID")
    and os.environ.get("MICROSOFT_CLIENT_SECRET")
)
if microsoft_enabled:
    oauth.register(
        name="microsoft",
        client_id=os.environ["MICROSOFT_CLIENT_ID"],
        client_secret: <REDACTED>
        server_metadata_url=f"https://login.microsoftonline.com/{microsoft_tenant_id}/v2.0/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email"},
    )


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column in columns:
        return
    try:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except sqlite3.OperationalError as error:
        if "duplicate column" not in str(error).lower():
            raise


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                google_sub TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                profile_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_identities (
                id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                email_at_link TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(provider, subject)
            );

            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                organization_type TEXT NOT NULL,
                profile_json TEXT NOT NULL DEFAULT '{}',
                created_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS customers (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                address TEXT NOT NULL DEFAULT '',
                contact_name TEXT NOT NULL DEFAULT '',
                contact_email TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(organization_id, name, address)
            );

            CREATE TABLE IF NOT EXISTS memberships (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                email TEXT NOT NULL,
                user_id TEXT REFERENCES users(id),
                roles_json TEXT NOT NULL,
                status TEXT NOT NULL,
                invited_by TEXT REFERENCES users(id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(organization_id, email)
            );

            CREATE TABLE IF NOT EXISTS organization_join_links (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                token_hash TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                created_by TEXT NOT NULL REFERENCES users(id),
                expires_at TEXT NOT NULL,
                accepted_count INTEGER NOT NULL DEFAULT 0,
                last_accepted_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assignments (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                purpose TEXT NOT NULL,
                desired_result TEXT NOT NULL,
                known_scope TEXT NOT NULL,
                known_constraints TEXT NOT NULL,
                location_context TEXT NOT NULL,
                execution_context TEXT NOT NULL,
                customer_id TEXT NOT NULL DEFAULT '',
                due_at TEXT NOT NULL,
                expected_submission TEXT NOT NULL,
                work_families_json TEXT NOT NULL,
                provider_id TEXT NOT NULL REFERENCES users(id),
                professional_responsible TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assignment_roles (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                role TEXT NOT NULL,
                email TEXT NOT NULL,
                user_id TEXT REFERENCES users(id),
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assignment_id, role, email)
            );

            CREATE TABLE IF NOT EXISTS planning_drafts (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assignment_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                submitted_by TEXT NOT NULL REFERENCES users(id),
                version INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL,
                status TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assignment_id, submitted_by, version)
            );

            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY,
                submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
                reviewer_id TEXT NOT NULL REFERENCES users(id),
                decision TEXT NOT NULL,
                summary TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS completion_drafts (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assignment_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS completion_submissions (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                submitted_by TEXT NOT NULL REFERENCES users(id),
                version INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL,
                status TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assignment_id, submitted_by, version)
            );

            CREATE TABLE IF NOT EXISTS completion_reviews (
                id TEXT PRIMARY KEY,
                completion_submission_id TEXT NOT NULL REFERENCES completion_submissions(id) ON DELETE CASCADE,
                reviewer_id TEXT NOT NULL REFERENCES users(id),
                decision TEXT NOT NULL,
                summary TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assignment_evidence (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                created_by TEXT NOT NULL REFERENCES users(id),
                phase TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                title TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                original_filename TEXT NOT NULL DEFAULT '',
                storage_name TEXT NOT NULL DEFAULT '',
                media_type TEXT NOT NULL DEFAULT '',
                byte_size INTEGER NOT NULL DEFAULT 0,
                content_sha256 TEXT NOT NULL,
                commitment_salt TEXT NOT NULL,
                commitment TEXT NOT NULL UNIQUE,
                registered_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                CHECK(phase IN ('before', 'during', 'after'))
            );

            CREATE TABLE IF NOT EXISTS document_packages (
                id TEXT PRIMARY KEY,
                assignment_id TEXT NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                submission_id TEXT NOT NULL REFERENCES submissions(id),
                version INTEGER NOT NULL,
                title TEXT NOT NULL,
                property_reference TEXT NOT NULL,
                summary TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                status TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                commitment_salt TEXT NOT NULL,
                commitment TEXT NOT NULL UNIQUE,
                receipt_signature TEXT NOT NULL,
                signing_method TEXT NOT NULL,
                midnight_status TEXT NOT NULL,
                created_by TEXT NOT NULL REFERENCES users(id),
                issued_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assignment_id, version)
            );

            CREATE TABLE IF NOT EXISTS document_access_grants (
                id TEXT PRIMARY KEY,
                package_id TEXT NOT NULL REFERENCES document_packages(id) ON DELETE CASCADE,
                recipient_email TEXT NOT NULL,
                recipient_user_id TEXT REFERENCES users(id),
                grant_type TEXT NOT NULL,
                purpose TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                granted_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(package_id, recipient_email, grant_type)
            );

            CREATE TABLE IF NOT EXISTS demo_document_access_grants (
                id TEXT PRIMARY KEY,
                package_id TEXT NOT NULL REFERENCES document_packages(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_key TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(package_id, user_id, recipient_key),
                CHECK(recipient_key IN ('owner', 'contractor', 'authority')),
                CHECK(status IN ('active', 'revoked'))
            );

            CREATE TABLE IF NOT EXISTS midnight_anchors (
                id TEXT PRIMARY KEY,
                package_id TEXT NOT NULL REFERENCES document_packages(id) ON DELETE CASCADE,
                commitment TEXT NOT NULL,
                operation TEXT NOT NULL,
                network TEXT NOT NULL,
                contract_address TEXT NOT NULL,
                status TEXT NOT NULL,
                transaction_id TEXT,
                block_hash TEXT,
                block_height INTEGER,
                verification_method TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                next_attempt_at TEXT NOT NULL DEFAULT '',
                locked_at TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL DEFAULT '',
                confirmed_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(package_id, operation),
                CHECK(operation IN ('register', 'revoke'))
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                organization_id TEXT REFERENCES organizations(id),
                assignment_id TEXT REFERENCES assignments(id),
                actor_id TEXT REFERENCES users(id),
                event_type TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_membership_user ON memberships(user_id, status);
            CREATE INDEX IF NOT EXISTS idx_join_link_org ON organization_join_links(organization_id, status, expires_at);
            CREATE INDEX IF NOT EXISTS idx_identity_user ON user_identities(user_id, provider);
            CREATE INDEX IF NOT EXISTS idx_customer_org ON customers(organization_id, lower(name));
            CREATE INDEX IF NOT EXISTS idx_assignment_org ON assignments(organization_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_assignment_role_user ON assignment_roles(user_id, role);
            CREATE INDEX IF NOT EXISTS idx_submission_assignment ON submissions(assignment_id, version DESC);
            CREATE INDEX IF NOT EXISTS idx_completion_submission_assignment ON completion_submissions(assignment_id, version DESC);
            CREATE INDEX IF NOT EXISTS idx_assignment_evidence_timeline ON assignment_evidence(assignment_id, registered_at);
            CREATE INDEX IF NOT EXISTS idx_document_package_assignment ON document_packages(assignment_id, version DESC);
            CREATE INDEX IF NOT EXISTS idx_document_package_org ON document_packages(organization_id, issued_at DESC);
            CREATE INDEX IF NOT EXISTS idx_document_grant_recipient ON document_access_grants(recipient_email, status);
            CREATE INDEX IF NOT EXISTS idx_demo_document_grant_user ON demo_document_access_grants(user_id, package_id);
            CREATE INDEX IF NOT EXISTS idx_midnight_anchor_queue ON midnight_anchors(status, next_attempt_at, created_at);
            """
        )
        ensure_column(connection, "organizations", "profile_json", "TEXT NOT NULL DEFAULT '{}'")
        ensure_column(connection, "assignments", "customer_id", "TEXT NOT NULL DEFAULT ''")
        connection.execute(
            """
            INSERT OR IGNORE INTO user_identities
                (id, provider, subject, user_id, email_at_link, created_at, updated_at)
            SELECT 'idn_google_' || id, 'google', google_sub, id, email, created_at, updated_at
            FROM users
            WHERE google_sub NOT LIKE 'identity:%'
            """
        )
        timestamp = now_iso()
        assignments_without_responsible_role = connection.execute(
            """SELECT a.id, a.professional_responsible
               FROM assignments a
               WHERE EXISTS (
                   SELECT 1 FROM assignment_roles worker
                   WHERE worker.assignment_id = a.id AND worker.role = 'assigned_worker'
               )
                 AND NOT EXISTS (
                   SELECT 1 FROM assignment_roles responsible
                   WHERE responsible.assignment_id = a.id AND responsible.role = 'professional_responsible'
               )"""
        ).fetchall()
        for assignment in assignments_without_responsible_role:
            workers = connection.execute(
                """SELECT ar.*, u.display_name
                   FROM assignment_roles ar
                   LEFT JOIN users u ON u.id = ar.user_id
                   WHERE ar.assignment_id = ? AND ar.role = 'assigned_worker'
                   ORDER BY ar.created_at, ar.email""",
                (assignment["id"],),
            ).fetchall()
            responsible_name = str(assignment["professional_responsible"] or "").strip().lower()
            responsible = next(
                (
                    worker for worker in workers
                    if responsible_name
                    and responsible_name in {
                        str(worker["display_name"] or "").strip().lower(),
                        str(worker["email"] or "").strip().lower(),
                    }
                ),
                workers[0],
            )
            connection.execute(
                """INSERT OR IGNORE INTO assignment_roles
                       (id, assignment_id, role, email, user_id, status, created_at, updated_at)
                   VALUES (?, ?, 'professional_responsible', ?, ?, ?, ?, ?)""",
                (
                    new_id("rol"), assignment["id"], responsible["email"], responsible["user_id"],
                    responsible["status"], timestamp, timestamp,
                ),
            )


def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def parse_json(value: str, default):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def document_commitment(manifest: dict, salt: str) -> str:
    return hashlib.sha256(bytes.fromhex(salt) + canonical_json(manifest)).hexdigest()


def document_signature(manifest: dict, commitment: str) -> str:
    message = canonical_json(manifest) + b":" + commitment.encode("ascii")
    return hmac.new(str(RECEIPT_SECRET).encode("utf-8"), message, hashlib.sha256).hexdigest()


def encrypt_document_manifest(manifest: dict, package_id: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(DOCUMENT_KEY).encrypt(nonce, canonical_json(manifest), package_id.encode("utf-8"))
    envelope = {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":"))


def decrypt_document_manifest(value: str, package_id: str) -> dict:
    envelope = parse_json(value, {})
    if envelope.get("algorithm") != "AES-256-GCM":
        return envelope
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    plaintext = AESGCM(DOCUMENT_KEY).decrypt(nonce, ciphertext, package_id.encode("utf-8"))
    return json.loads(plaintext.decode("utf-8"))


def timestamp_expired(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed <= datetime.now(UTC)


def join_token_hash(token: <REDACTED>
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def qr_data_url(value: str) -> str:
    image = qrcode.make(value, image_factory=SvgPathImage, box_size=8, border=2)
    output = io.BytesIO()
    image.save(output)
    encoded = base64.b64encode(output.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def midnight_anchor_summary(connection: sqlite3.Connection, package: sqlite3.Row, language: str = "no") -> dict:
    rows = connection.execute(
        "SELECT * FROM midnight_anchors WHERE package_id = ? ORDER BY created_at",
        (package["id"],),
    ).fetchall()
    anchors = {row["operation"]: row for row in rows}
    registration = anchors.get("register")
    revocation = anchors.get("revoke")

    def public_transaction(row: sqlite3.Row | None) -> dict | None:
        if not row or row["status"] != "confirmed":
            return None
        return {
            "id": row["transaction_id"] or None,
            "block_hash": row["block_hash"] or None,
            "block_height": row["block_height"],
            "verification_method": row["verification_method"] or "finalized_transaction",
        }

    status = package["midnight_status"]
    statements = {
        "queued": "Dokumentforpliktelsen venter på forankring. Rapportinnhold og personopplysninger forblir private.",
        "proving": "Det genereres et privat bevis for dokumentforpliktelsen. Rapportinnholdet sendes ikke til Midnight.",
        "failed": "Forankringen er ikke bekreftet. Den lokale integritetskvitteringen gjelder fortsatt, og et nytt forsøk planlegges.",
        "confirmed": "Dokumentforpliktelsen er bekreftet på Midnight. Rapportinnhold og personopplysninger forblir private i FieldSeal.",
        "revocation_queued": "Tilbakekalling venter på registrering på Midnight.",
        "revocation_pending": "Tilbakekalling behandles på Midnight.",
        "revocation_failed": "Tilbakekallingen er ikke bekreftet på Midnight ennå. Et nytt forsøk planlegges.",
        "revoked": "Dokumentforpliktelsen er registrert som tilbakekalt på Midnight.",
    }
    if language == "en":
        statements = {
            "queued": "The document commitment is waiting to be anchored. Report content and personal data remain private.",
            "proving": "A private proof is being generated for the document commitment. Report content is not sent to Midnight.",
            "failed": "The anchor is not confirmed. The local integrity receipt remains valid and a retry is scheduled.",
            "confirmed": "The document commitment is confirmed on Midnight. Report content and personal data remain private in FieldSeal.",
            "revocation_queued": "Revocation is waiting to be registered on Midnight.",
            "revocation_pending": "Revocation is being processed on Midnight.",
            "revocation_failed": "Revocation is not yet confirmed on Midnight. A retry is scheduled.",
            "revoked": "The document commitment is recorded as revoked on Midnight.",
        }
    return {
        "status": status,
        "network": (registration or revocation)["network"] if registration or revocation else None,
        "contract_address": (registration or revocation)["contract_address"] if registration or revocation else None,
        "transaction": public_transaction(registration),
        "revocation_transaction": public_transaction(revocation),
        "statement": statements.get(
            status,
            (
                "No anchoring is claimed until a confirmed transaction or contract state can be checked independently."
                if language == "en"
                else "Ingen forankring hevdes før en bekreftet transaksjon eller kontrakttilstand kan kontrolleres uavhengig."
            ),
        ),
    }


def enqueue_midnight_anchor(
    connection: sqlite3.Connection,
    package_id: str,
    commitment: str,
    operation: str,
) -> bool:
    if not MIDNIGHT_READY or operation not in {"register", "revoke"}:
        return False
    existing = connection.execute(
        "SELECT status FROM midnight_anchors WHERE package_id = ? AND operation = ?",
        (package_id, operation),
    ).fetchone()
    if existing and existing["status"] == "confirmed":
        return False
    timestamp = now_iso()
    if existing:
        connection.execute(
            """
            UPDATE midnight_anchors
            SET commitment = ?, network = ?, contract_address = ?, status = 'queued',
                last_error = '', next_attempt_at = '', locked_at = '', updated_at = ?
            WHERE package_id = ? AND operation = ?
            """,
            (commitment, MIDNIGHT_NETWORK, MIDNIGHT_CONTRACT_ADDRESS, timestamp, package_id, operation),
        )
    else:
        connection.execute(
            """
            INSERT INTO midnight_anchors
                (id, package_id, commitment, operation, network, contract_address, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)
            """,
            (
                new_id("mda"),
                package_id,
                commitment,
                operation,
                MIDNIGHT_NETWORK,
                MIDNIGHT_CONTRACT_ADDRESS,
                timestamp,
                timestamp,
            ),
        )
    package_status = "queued" if operation == "register" else "revocation_queued"
    connection.execute(
        "UPDATE document_packages SET midnight_status = ?, updated_at = ? WHERE id = ?",
        (package_status, timestamp, package_id),
    )
    return True


def microsoft_identity_from_claims(info: dict) -> dict | None:
    tenant_id = str(info.get("tid") or "").strip().lower()
    if not tenant_id or tenant_id != microsoft_tenant_id.lower():
        return None
    email = normalize_email(info.get("email") or info.get("preferred_username"))
    if not email or "@" not in email:
        return None
    domain = email.rsplit("@", 1)[1]
    if microsoft_allowed_domains and domain not in microsoft_allowed_domains:
        return None
    object_id = str(info.get("oid") or info.get("sub") or "").strip()
    if not object_id:
        return None
    return {
        "subject": f"{tenant_id}:{object_id}",
        "email": email,
        "name": str(info.get("name") or email).strip(),
    }


def upsert_user_identity(provider: str, subject: str, email: str, name: str) -> str:
    timestamp = now_iso()
    email = normalize_email(email)
    with db() as connection:
        identity_user = connection.execute(
            """
            SELECT u.* FROM user_identities i
            JOIN users u ON u.id = i.user_id
            WHERE i.provider = ? AND i.subject = ?
            """,
            (provider, subject),
        ).fetchone()
        email_user = connection.execute("SELECT * FROM users WHERE lower(email) = ?", (email,)).fetchone()
        if identity_user and email_user and identity_user["id"] != email_user["id"]:
            abort(409, "Innloggingsidentiteten og e-postadressen tilhører ulike FieldSeal-brukere")
        user = identity_user or email_user
        if user:
            user_id = user["id"]
            connection.execute(
                "UPDATE users SET email = ?, display_name = ?, updated_at = ? WHERE id = ?",
                (email, name or email, timestamp, user_id),
            )
        else:
            user_id = new_id("usr")
            legacy_subject = subject if provider == "google" else f"identity:{provider}:{subject}"
            connection.execute(
                "INSERT INTO users (id, google_sub, email, display_name, profile_json, created_at, updated_at) VALUES (?, ?, ?, ?, '{}', ?, ?)",
                (user_id, legacy_subject, email, name or email, timestamp, timestamp),
            )
        connection.execute(
            """
            INSERT INTO user_identities (id, provider, subject, user_id, email_at_link, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, subject) DO UPDATE SET
                user_id = excluded.user_id,
                email_at_link = excluded.email_at_link,
                updated_at = excluded.updated_at
            """,
            (new_id("idn"), provider, subject, user_id, email, timestamp, timestamp),
        )
        refreshed = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        claim_invitations(connection, refreshed)
    return user_id


def json_payload() -> dict:
    if request.content_length and request.content_length > MAX_JSON_BYTES:
        abort(413)
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        abort(400, "Forespørselen må inneholde et JSON-objekt")
    return value


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                abort(401)
            return redirect("/login")
        return view(*args, **kwargs)

    return wrapped


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def claim_invitations(connection: sqlite3.Connection, user: sqlite3.Row) -> None:
    timestamp = now_iso()
    email = normalize_email(user["email"])
    connection.execute(
        "UPDATE memberships SET user_id = ?, status = 'active', updated_at = ? WHERE lower(email) = ? AND (user_id IS NULL OR user_id = ?)",
        (user["id"], timestamp, email, user["id"]),
    )
    connection.execute(
        "UPDATE assignment_roles SET user_id = ?, status = CASE WHEN status = 'invited' THEN 'assigned' ELSE status END, updated_at = ? WHERE lower(email) = ? AND (user_id IS NULL OR user_id = ?)",
        (user["id"], timestamp, email, user["id"]),
    )
    connection.execute(
        "UPDATE document_access_grants SET recipient_user_id = ?, updated_at = ? WHERE lower(recipient_email) = ? AND (recipient_user_id IS NULL OR recipient_user_id = ?)",
        (user["id"], timestamp, email, user["id"]),
    )


def audit(connection: sqlite3.Connection, event_type: str, actor_id: str | None, organization_id: str | None = None, assignment_id: str | None = None, detail: dict | None = None) -> None:
    connection.execute(
        "INSERT INTO audit_events (id, organization_id, assignment_id, actor_id, event_type, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id("evt"), organization_id, assignment_id, actor_id, event_type, json.dumps(detail or {}, separators=(",", ":")), now_iso()),
    )


def membership_roles(connection: sqlite3.Connection, organization_id: str, user_id: str) -> set[str]:
    row = connection.execute(
        "SELECT roles_json FROM memberships WHERE organization_id = ? AND user_id = ? AND status = 'active'",
        (organization_id, user_id),
    ).fetchone()
    return set(parse_json(row["roles_json"], [])) if row else set()


def require_org_role(connection: sqlite3.Connection, organization_id: str, user_id: str, allowed: set[str]) -> set[str]:
    roles = membership_roles(connection, organization_id, user_id)
    if not roles.intersection(allowed):
        abort(403)
    return roles


def assignment_row(connection: sqlite3.Connection, assignment_id: str) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
    if not row:
        abort(404)
    return row


def assignment_roles(connection: sqlite3.Connection, assignment_id: str) -> list[dict]:
    rows = connection.execute(
        "SELECT ar.*, u.display_name FROM assignment_roles ar LEFT JOIN users u ON u.id = ar.user_id WHERE ar.assignment_id = ? ORDER BY ar.role, ar.email",
        (assignment_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def user_assignment_roles(connection: sqlite3.Connection, assignment_id: str, user: sqlite3.Row) -> set[str]:
    rows = connection.execute(
        "SELECT role FROM assignment_roles WHERE assignment_id = ? AND (user_id = ? OR lower(email) = ?)",
        (assignment_id, user["id"], normalize_email(user["email"])),
    ).fetchall()
    return {row["role"] for row in rows}


def assigned_worker_role(connection: sqlite3.Connection, assignment_id: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT ar.*, u.display_name FROM assignment_roles ar LEFT JOIN users u ON u.id = ar.user_id WHERE ar.assignment_id = ? AND ar.role = 'assigned_worker' ORDER BY ar.created_at LIMIT 1",
        (assignment_id,),
    ).fetchone()


def assigned_worker_roles(connection: sqlite3.Connection, assignment_id: str) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT ar.*, u.display_name FROM assignment_roles ar LEFT JOIN users u ON u.id = ar.user_id WHERE ar.assignment_id = ? AND ar.role = 'assigned_worker' ORDER BY ar.created_at, ar.email",
        (assignment_id,),
    ).fetchall()


def professional_responsible_role(connection: sqlite3.Connection, assignment_id: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT ar.*, u.display_name FROM assignment_roles ar LEFT JOIN users u ON u.id = ar.user_id WHERE ar.assignment_id = ? AND ar.role = 'professional_responsible' ORDER BY ar.updated_at DESC LIMIT 1",
        (assignment_id,),
    ).fetchone()


def serialize_assignment_person(role: sqlite3.Row) -> dict:
    return {
        "email": role["email"],
        "user_id": role["user_id"],
        "display_name": role["display_name"] or role["email"],
        "status": role["status"],
    }


def assignment_is_available(connection: sqlite3.Connection, assignment: sqlite3.Row) -> bool:
    return assignment["status"] == "published" and assigned_worker_role(connection, assignment["id"]) is None


def assignment_has_artifacts(connection: sqlite3.Connection, assignment_id: str) -> bool:
    tables = (
        "planning_drafts",
        "submissions",
        "completion_drafts",
        "completion_submissions",
        "assignment_evidence",
        "document_packages",
    )
    return any(
        connection.execute(f"SELECT 1 FROM {table} WHERE assignment_id = ? LIMIT 1", (assignment_id,)).fetchone()
        for table in tables
    )


def serialize_assignment_for(connection: sqlite3.Connection, assignment: sqlite3.Row) -> dict:
    value = serialize_assignment(assignment)
    assigned = assigned_worker_roles(connection, assignment["id"])
    responsible = professional_responsible_role(connection, assignment["id"])
    value["is_available"] = assignment["status"] == "published" and not assigned
    value["assigned_workers"] = [serialize_assignment_person(role) for role in assigned]
    value["assigned_worker"] = serialize_assignment_person(assigned[0]) if assigned else None
    value["professional_responsible_user"] = serialize_assignment_person(responsible) if responsible else None
    return value


def can_access_assignment(connection: sqlite3.Connection, assignment: sqlite3.Row, user: sqlite3.Row) -> bool:
    if assignment["provider_id"] == user["id"]:
        return True
    if user_assignment_roles(connection, assignment["id"], user):
        return True
    organization_roles = membership_roles(connection, assignment["organization_id"], user["id"])
    if organization_roles.intersection({"admin", "task_provider"}):
        return True
    return "worker" in organization_roles and assignment_is_available(connection, assignment)


def document_package_row(connection: sqlite3.Connection, package_id: str) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT p.*, a.title AS assignment_title, a.provider_id, o.name AS organization_name,
               u.display_name AS issued_by_name
        FROM document_packages p
        JOIN assignments a ON a.id = p.assignment_id
        JOIN organizations o ON o.id = p.organization_id
        JOIN users u ON u.id = p.created_by
        WHERE p.id = ?
        """,
        (package_id,),
    ).fetchone()
    if not row:
        abort(404)
    return row


def demo_document_package_row(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT p.*, a.execution_context
        FROM document_packages p
        JOIN assignments a ON a.id = p.assignment_id
        WHERE a.title = ? AND a.execution_context = 'training_synthetic'
        ORDER BY p.issued_at DESC, p.version DESC
        LIMIT 1
        """,
        (DEMO_ASSIGNMENT_TITLE,),
    ).fetchone()
    if not row:
        abort(404, "The synthetic Midnight demonstration report is not available")
    return row


def demo_document_access_state(connection: sqlite3.Connection, package_id: str, user_id: str) -> dict:
    rows = connection.execute(
        """
        SELECT recipient_key, status, expires_at, created_at, updated_at
        FROM demo_document_access_grants
        WHERE package_id = ? AND user_id = ?
        """,
        (package_id, user_id),
    ).fetchall()
    saved = {row["recipient_key"]: row for row in rows}
    recipients = []
    for recipient_key, preset in DEMO_ACCESS_PRESETS.items():
        row = saved.get(recipient_key)
        expired = bool(row and timestamp_expired(row["expires_at"]))
        active = bool(row and row["status"] == "active" and not expired)
        recipients.append(
            {
                "key": recipient_key,
                "active": active,
                "status": "active" if active else "expired" if expired else row["status"] if row else "not_granted",
                "duration_kind": preset["duration_kind"],
                "purpose": preset["purpose"],
                "expires_at": row["expires_at"] if row else "",
                "granted_at": row["created_at"] if row else "",
                "updated_at": row["updated_at"] if row else "",
            }
        )
    return {"package_id": package_id, "recipients": recipients}


def document_grants_for(connection: sqlite3.Connection, package_id: str) -> list[dict]:
    rows = connection.execute(
        """
        SELECT id, recipient_email, grant_type, purpose, expires_at, status, created_at, updated_at
        FROM document_access_grants
        WHERE package_id = ?
        ORDER BY CASE grant_type WHEN 'owner' THEN 0 WHEN 'contractor' THEN 1 ELSE 2 END, recipient_email
        """,
        (package_id,),
    ).fetchall()
    return [{**dict(row), "expired": timestamp_expired(row["expires_at"])} for row in rows]


def can_manage_document_package(connection: sqlite3.Connection, package: sqlite3.Row, user: sqlite3.Row) -> bool:
    if package["created_by"] == user["id"] or package["provider_id"] == user["id"]:
        return True
    return bool(membership_roles(connection, package["organization_id"], user["id"]).intersection({"admin", "task_provider"}))


def can_view_document_package(connection: sqlite3.Connection, package: sqlite3.Row, user: sqlite3.Row) -> bool:
    if can_manage_document_package(connection, package, user):
        return True
    assignment = assignment_row(connection, package["assignment_id"])
    if can_access_assignment(connection, assignment, user):
        return True
    if package["status"] == "revoked":
        return False
    rows = connection.execute(
        """
        SELECT expires_at FROM document_access_grants
        WHERE package_id = ? AND status = 'active'
          AND (recipient_user_id = ? OR lower(recipient_email) = ?)
        """,
        (package["id"], user["id"], normalize_email(user["email"])),
    ).fetchall()
    return any(not timestamp_expired(row["expires_at"]) for row in rows)


def serialize_document_package(connection: sqlite3.Connection, package: sqlite3.Row, user: sqlite3.Row) -> dict:
    manageable = can_manage_document_package(connection, package, user)
    try:
        manifest = decrypt_document_manifest(package["manifest_json"], package["id"])
    except (InvalidTag, KeyError, ValueError):
        manifest = {}
    protected = manifest.get("package", {})
    accepted_submission = manifest.get("accepted_submission", {})
    snapshot = accepted_submission.get("snapshot", {})
    accepted_completion = manifest.get("accepted_completion", {})
    completion_snapshot = accepted_completion.get("snapshot", {})
    assignment_snapshot = manifest.get("assignment", {})
    evidence_timeline = []
    for evidence in manifest.get("evidence_timeline", []):
        visible_evidence = {key: value for key, value in evidence.items() if key not in {"commitment_salt", "created_by_user_id"}}
        visible_evidence["download_url"] = f"/api/assignment-evidence/{evidence.get('id', '')}/file"
        evidence_timeline.append(visible_evidence)
    customer = connection.execute(
        """SELECT a.customer_id, a.work_families_json,
                  COALESCE(c.name, '') AS customer_name, COALESCE(c.address, '') AS customer_address
           FROM assignments a LEFT JOIN customers c ON c.id = a.customer_id
           WHERE a.id = ?""",
        (package["assignment_id"],),
    ).fetchone()
    midnight = midnight_anchor_summary(connection, package)
    return {
        "id": package["id"],
        "assignment_id": package["assignment_id"],
        "assignment_title": package["assignment_title"],
        "organization_id": package["organization_id"],
        "organization_name": package["organization_name"],
        "customer_id": customer["customer_id"] if customer else "",
        "customer_name": customer["customer_name"] if customer else "",
        "customer_address": customer["customer_address"] if customer else "",
        "work_families": parse_json(customer["work_families_json"], []) if customer else [],
        "submission_id": package["submission_id"],
        "version": package["version"],
        "title": protected.get("title", package["title"]),
        "property_reference": protected.get("property_reference", package["property_reference"]),
        "summary": protected.get("summary", package["summary"]),
        "owner_email": protected.get("owner_email", package["owner_email"]),
        "report": {
            "tests_and_results": protected.get("tests_and_results", ""),
            "deviations": protected.get("deviations", ""),
            "handover_notes": protected.get("handover_notes", ""),
            "safe_closure": protected.get("safe_closure", ""),
            "evidence_references": protected.get("evidence_references", ""),
            "accepted_plan_version": accepted_submission.get("version"),
            "planning": snapshot.get("planning", {}),
            "reviews": accepted_submission.get("reviews", []),
            "accepted_completion_version": accepted_completion.get("version"),
            "completion": completion_snapshot.get("completion", {}),
            "completion_reviews": accepted_completion.get("reviews", []),
            "evidence_timeline": evidence_timeline,
        } if protected else {},
        "status": package["status"],
        "commitment": package["commitment"],
        "signing_method": package["signing_method"],
        "midnight_status": midnight["status"],
        "midnight": midnight,
        "issued_at": package["issued_at"],
        "issued_by_name": package["issued_by_name"],
        "content_status": "available" if protected else "unreadable",
        "is_demonstration": assignment_snapshot.get("execution_context") in {"training_synthetic", "supervised_practice"},
        "can_manage": manageable,
        "access_scope": "organization" if manageable or user_assignment_roles(connection, package["assignment_id"], user) else "shared",
        "grants": document_grants_for(connection, package["id"]) if manageable else [],
    }


def document_packages_for_assignment(connection: sqlite3.Connection, assignment_id: str, user: sqlite3.Row) -> list[dict]:
    rows = connection.execute(
        """
        SELECT p.*, a.title AS assignment_title, a.provider_id, o.name AS organization_name,
               u.display_name AS issued_by_name
        FROM document_packages p
        JOIN assignments a ON a.id = p.assignment_id
        JOIN organizations o ON o.id = p.organization_id
        JOIN users u ON u.id = p.created_by
        WHERE p.assignment_id = ?
        ORDER BY p.version DESC
        """,
        (assignment_id,),
    ).fetchall()
    return [serialize_document_package(connection, row, user) for row in rows if can_view_document_package(connection, row, user)]


def serialize_assignment(row: sqlite3.Row) -> dict:
    value = dict(row)
    value["work_families"] = parse_json(value.pop("work_families_json"), [])
    return value


def customer_location(customer: sqlite3.Row) -> str:
    name = str(customer["name"]).strip()
    address = str(customer["address"]).strip()
    return f"{name} · {address}" if address else name


def evidence_rows_for(connection: sqlite3.Connection, assignment_id: str) -> list[sqlite3.Row]:
    return connection.execute(
        """SELECT e.*, u.display_name AS registered_by_name
           FROM assignment_evidence e
           JOIN users u ON u.id = e.created_by
           WHERE e.assignment_id = ?
           ORDER BY e.registered_at, e.id""",
        (assignment_id,),
    ).fetchall()


def serialize_evidence(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "assignment_id": row["assignment_id"],
        "phase": row["phase"],
        "evidence_type": row["evidence_type"],
        "title": row["title"],
        "note": row["note"],
        "original_filename": row["original_filename"],
        "media_type": row["media_type"],
        "byte_size": row["byte_size"],
        "content_sha256": row["content_sha256"],
        "commitment": row["commitment"],
        "registered_at": row["registered_at"],
        "registered_by_name": row["registered_by_name"],
        "download_url": f"/api/assignment-evidence/{row['id']}/file" if row["storage_name"] else "",
    }


def evidence_manifest_item(row: sqlite3.Row) -> dict:
    item = serialize_evidence(row)
    item.pop("download_url", None)
    return {
        **item,
        "created_by_user_id": row["created_by"],
        "commitment_salt": row["commitment_salt"],
    }


def source_matches(source: dict, families: list[str], planning: dict) -> bool:
    if not set(source.get("families", [])).intersection(families):
        return False
    conditions = source.get("conditions", {})
    if conditions.get("mixed_families") and not {"electro", "ekom"}.issubset(set(families)):
        return False
    for field, allowed in conditions.items():
        if field == "mixed_families":
            continue
        if str(planning.get(field, "unknown")) not in allowed:
            return False
    return True


def considerations_for(assignment: sqlite3.Row, planning: dict) -> list[dict]:
    families = parse_json(assignment["work_families_json"], [])
    policy = load_policy()
    results = []
    for source in policy["sources"]:
        if not source_matches(source, families, planning):
            continue
        results.append(
            {
                "id": source["id"],
                "source_class": source["source_class"],
                "title": source["title"],
                "publisher": source["publisher"],
                "reference": source["reference"],
                "url": source["url"],
                "responsible_actor": source["responsible_actor"],
                "consideration": source["consideration"],
                "expected_evidence": source["expected_evidence"],
                "trigger": source["trigger"],
                "policy_version": policy["version"],
                "review_owner": policy["review_owner"],
                "uncertainty": "Kontroller relevans og gjeldende kildetekst før profesjonell utførelse.",
            }
        )
    return results


def submissions_for(connection: sqlite3.Connection, assignment_id: str) -> list[dict]:
    rows = connection.execute(
        "SELECT s.*, u.display_name AS submitted_by_name FROM submissions s JOIN users u ON u.id = s.submitted_by WHERE assignment_id = ? ORDER BY version DESC",
        (assignment_id,),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["snapshot"] = parse_json(item.pop("snapshot_json"), {})
        reviews = connection.execute(
            "SELECT r.*, u.display_name AS reviewer_name FROM reviews r JOIN users u ON u.id = r.reviewer_id WHERE submission_id = ? ORDER BY created_at",
            (row["id"],),
        ).fetchall()
        item["reviews"] = [{**dict(review), "findings": parse_json(review["findings_json"], [])} for review in reviews]
        for review in item["reviews"]:
            review.pop("findings_json", None)
        result.append(item)
    return result


def completion_submissions_for(connection: sqlite3.Connection, assignment_id: str) -> list[dict]:
    rows = connection.execute(
        """SELECT s.*, u.display_name AS submitted_by_name
           FROM completion_submissions s
           JOIN users u ON u.id = s.submitted_by
           WHERE assignment_id = ? ORDER BY version DESC""",
        (assignment_id,),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["snapshot"] = parse_json(item.pop("snapshot_json"), {})
        reviews = connection.execute(
            """SELECT r.*, u.display_name AS reviewer_name
               FROM completion_reviews r
               JOIN users u ON u.id = r.reviewer_id
               WHERE completion_submission_id = ? ORDER BY r.created_at""",
            (row["id"],),
        ).fetchall()
        item["reviews"] = [{**dict(review), "findings": parse_json(review["findings_json"], [])} for review in reviews]
        for review in item["reviews"]:
            review.pop("findings_json", None)
        result.append(item)
    return result


@app.before_request
def protect_api() -> None:
    if request.path.startswith("/api/internal/midnight/"):
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {MIDNIGHT_WORKER_TOKEN}" if MIDNIGHT_WORKER_TOKEN else ""
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(404)
        return
    if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = str(session.get("csrf", ""))
        supplied = str(request.headers.get("X-CSRF-Token", ""))
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(403, "Ugyldig sikkerhetskode for forespørselen")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    if request.path == "/sw.js":
        response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.errorhandler(HTTPException)
def http_error(error: HTTPException):
    if request.path.startswith("/api/"):
        response = jsonify({"message": str(error.description or error.name)})
        response.status_code = int(error.code or 500)
        return response
    return error


@app.get("/login")
def login():
    if current_user():
        pending_invite = str(session.get("pending_org_invite", ""))
        return redirect(url_for("join_organization", token: <REDACTED>
    providers = []
    if microsoft_enabled:
        providers.append("<a class='microsoft' href='/auth/microsoft'>Fortsett med Microsoft</a>")
    if google_enabled:
        providers.append("<a class='google' href='/auth/google'>Fortsett med Google</a>")
    provider_links = "".join(providers) or "<p class='unavailable'>Ingen innloggingsleverandør er konfigurert.</p>"
    return f"""<!doctype html><html lang='no'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='theme-color' content='#f0502f'><title>Logg inn | FieldSeal</title><script src='/static/i18n.js?v=22' defer></script><style>
    *{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7f8;color:#24252b;font-family:Inter,system-ui,sans-serif}}main{{width:min(460px,calc(100vw - 28px));background:white;border:1px solid #e5e5e8;padding:40px;border-radius:5px;box-shadow:0 12px 36px #24252b0d}}.language-row{{display:flex;justify-content:flex-end;align-items:center;gap:7px;margin-bottom:28px}}.language-row span{{color:#6d7078;font-size:10px;font-weight:800;text-transform:uppercase}}.language-row select{{min-height:36px;border:1px solid #c9cbd1;border-radius:4px;background:white;padding:0 9px;font-weight:700}}.mark{{display:grid;place-items:center;width:48px;height:48px;border-radius:5px;background:#f0502f;color:white;font-weight:900;font-size:23px}}h1{{margin:22px 0 8px;font-size:34px;letter-spacing:0}}p{{margin:0 0 26px;color:#6d7078;line-height:1.55}}.providers{{display:grid;gap:10px}}a{{display:flex;align-items:center;justify-content:center;min-height:50px;border:1px solid transparent;border-radius:4px;color:white;text-decoration:none;font-weight:800}}a.microsoft{{background:#185abd}}a.google{{background:#f0502f}}a:hover{{filter:brightness(.92)}}.unavailable{{padding:14px;border:1px solid #e5e5e8;border-radius:4px;background:#f7f7f8;color:#6d7078}}small{{display:block;margin-top:20px;padding-top:18px;border-top:1px solid #e5e5e8;color:#6d7078;line-height:1.5}}
    </style></head><body><main><label class='language-row'><span>Språk</span><select data-language-select aria-label='Språk'><option value='no'>Norsk</option><option value='en'>English</option></select></label><div class='mark'>F</div><h1>FieldSeal</h1><p>Logg inn for å opprette ditt eget arbeidsområde eller åpne en invitasjon.</p><div class='providers'>{provider_links}</div><small>Oppdrag gir ikke i seg selv kompetanse, autorisasjon eller faglig ansvar. Kilder og vurderinger skal kontrolleres for den konkrete jobben.</small></main></body></html>"""


@app.get("/auth/google")
def google_start():
    if not google_enabled:
        abort(503)
    return oauth.google.authorize_redirect(url_for("google_callback", _external=True, _scheme="https"))


@app.get("/auth/google/callback")
def google_callback():
    if not google_enabled:
        abort(503)
    token: <REDACTED>
    info = token.get("userinfo") or oauth.google.userinfo()
    if not info.get("email_verified"):
        abort(403)
    email = normalize_email(info["email"])
    user_id = upsert_user_identity("google", str(info["sub"]), email, info.get("name") or email)
    pending_invite = str(session.get("pending_org_invite", ""))
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    if pending_invite:
        session["pending_org_invite"] = pending_invite
    csrf_token()
    return redirect(url_for("join_organization", token: <REDACTED>


@app.get("/auth/microsoft")
def microsoft_start():
    if not microsoft_enabled:
        abort(503, "Microsoft-pålogging er ikke konfigurert")
    return oauth.microsoft.authorize_redirect(url_for("microsoft_callback", _external=True, _scheme="https"))


@app.get("/auth/microsoft/callback")
def microsoft_callback():
    if not microsoft_enabled:
        abort(503, "Microsoft-pålogging er ikke konfigurert")
    token: <REDACTED>
    info = token.get("userinfo") or oauth.microsoft.parse_id_token(token)
    identity = microsoft_identity_from_claims(dict(info or {}))
    if not identity:
        abort(403, "Microsoft-kontoen tilhører ikke den konfigurerte skoleorganisasjonen")
    user_id = upsert_user_identity("microsoft", identity["subject"], identity["email"], identity["name"])
    pending_invite = str(session.get("pending_org_invite", ""))
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    if pending_invite:
        session["pending_org_invite"] = pending_invite
    csrf_token()
    return redirect(url_for("join_organization", token: <REDACTED>


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/join/<token>", methods=["GET", "POST"])
def join_organization(token: <REDACTED>
    token: <REDACTED>
    if len(token) < 24:
        abort(404)
    with db() as connection:
        link = connection.execute(
            """SELECT l.*, o.name AS organization_name
               FROM organization_join_links l
               JOIN organizations o ON o.id = l.organization_id
               WHERE l.token_hash = ?""",
            (join_token_hash(token),),
        ).fetchone()
        if not link:
            abort(404)
        if link["status"] != "active" or timestamp_expired(link["expires_at"]):
            abort(410, "Invitasjonslenken er utløpt eller trukket tilbake")
        user = current_user()
        if not user:
            session["pending_org_invite"] = token
            return redirect("/login")
        if request.method == "POST":
            supplied = str(request.form.get("csrf", ""))
            expected = str(session.get("csrf", ""))
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(403)
            timestamp = now_iso()
            existing = connection.execute(
                "SELECT * FROM memberships WHERE organization_id = ? AND lower(email) = ?",
                (link["organization_id"], normalize_email(user["email"])),
            ).fetchone()
            if existing:
                roles = parse_json(existing["roles_json"], []) or ["member"]
                connection.execute(
                    "UPDATE memberships SET user_id = ?, roles_json = ?, status = 'active', updated_at = ? WHERE id = ?",
                    (user["id"], json.dumps(roles), timestamp, existing["id"]),
                )
            else:
                connection.execute(
                    """INSERT INTO memberships
                       (id, organization_id, email, user_id, roles_json, status, invited_by, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                    (
                        new_id("mem"), link["organization_id"], normalize_email(user["email"]), user["id"],
                        json.dumps(["member"]), link["created_by"], timestamp, timestamp,
                    ),
                )
            connection.execute(
                "UPDATE organization_join_links SET accepted_count = accepted_count + 1, last_accepted_at = ?, updated_at = ? WHERE id = ?",
                (timestamp, timestamp, link["id"]),
            )
            audit(
                connection, "membership.joined", user["id"], link["organization_id"],
                detail={"join_link_id": link["id"], "initial_roles": ["member"]},
            )
            session.pop("pending_org_invite", None)
            return redirect("/?joined=1")
    organization_name = html.escape(str(link["organization_name"]))
    user_name = html.escape(str(user["display_name"] or user["email"]))
    csrf = html.escape(csrf_token(), quote=True)
    expires_at = html.escape(link["expires_at"][:10])
    return f"""<!doctype html><html lang='no'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='theme-color' content='#f0502f'><title>Bli med | FieldSeal</title><style>
    *{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7f8;color:#24252b;font-family:Inter,system-ui,sans-serif}}main{{width:min(520px,calc(100vw - 28px));background:white;border:1px solid #e5e5e8;padding:38px;border-radius:5px;box-shadow:0 12px 36px #24252b0d}}.mark{{display:grid;place-items:center;width:46px;height:46px;border-radius:5px;background:#f0502f;color:white;font-size:22px;font-weight:900}}h1{{margin:22px 0 8px;font-size:30px}}p{{color:#6d7078;line-height:1.55}}.facts{{margin:24px 0;border:1px solid #e5e5e8}}.facts div{{display:grid;grid-template-columns:130px 1fr;gap:14px;padding:12px 14px;border-bottom:1px solid #e5e5e8}}.facts div:last-child{{border:0}}.facts span{{color:#6d7078;font-size:12px}}.facts strong{{font-size:13px}}.notice{{border-left:4px solid #255a83;background:#edf4f8;padding:14px;font-size:13px;line-height:1.5}}button{{width:100%;min-height:50px;margin-top:22px;border:0;border-radius:4px;background:#f0502f;color:white;font:inherit;font-weight:800;cursor:pointer}}small{{display:block;margin-top:16px;color:#6d7078;line-height:1.45}}
    </style></head><body><main><div class='mark'>F</div><h1>Bli med i {organization_name}</h1><p>Du blir først lagt til som medlem. En leder kan senere gi deg riktig rolle og tilgang til arbeidsfunksjoner.</p><div class='facts'><div><span>Organisasjon</span><strong>{organization_name}</strong></div><div><span>Logget inn som</span><strong>{user_name}</strong></div><div><span>Lenken gjelder til</span><strong>{expires_at}</strong></div></div><div class='notice'>Medlemskap gir ikke automatisk tilgang til oppdrag, kundedata eller rapporter. Rapporttilgang deles separat og kan trekkes tilbake.</div><form method='post'><input type='hidden' name='csrf' value='{csrf}'><button type='submit'>Bli med i organisasjonen</button></form><small>Invitasjonen gir ingen faglig godkjenning, kompetanse eller myndighetsrolle.</small></main></body></html>"""


@app.get("/")
@login_required
def index():
    return send_file(STATIC_DIR / "index.html")


@app.get("/en")
def english_entry():
    return redirect("/en/demo-report")


@app.get("/demo-report")
def demo_report_entry():
    return redirect("/en/demo-report")


@app.get("/<language>/demo-report")
def localized_demo_report(language):
    if language not in DEMO_REPORT_LANGUAGES:
        abort(404)
    return send_file(STATIC_DIR / "midnight-demo.en.html")


@app.get("/sw.js")
def service_worker():
    return send_file(STATIC_DIR / "sw.js", mimetype="application/javascript")


@app.get("/healthz")
def health():
    with db() as connection:
        connection.execute("SELECT 1").fetchone()
    return jsonify({"status": "ok", "service": "esense", "generation": "documentation-and-assurance"})


@app.get("/api/public/midnight-demo")
def public_midnight_demo():
    with db() as connection:
        package = demo_document_package_row(connection)
        try:
            manifest = decrypt_document_manifest(package["manifest_json"], package["id"])
            calculated_commitment = document_commitment(manifest, package["commitment_salt"])
            calculated_signature = document_signature(manifest, package["commitment"])
            commitment_valid = hmac.compare_digest(calculated_commitment, package["commitment"])
            signature_valid = hmac.compare_digest(calculated_signature, package["receipt_signature"])
        except (InvalidTag, KeyError, ValueError):
            commitment_valid = False
            signature_valid = False
        midnight = midnight_anchor_summary(connection, package, "en")

    midnight_status = midnight["status"]
    response = jsonify(
        {
            "demonstration": True,
            "notice": "All people, places, work and measurements in this report are fictional.",
            "report": DEMO_PUBLIC_REPORT,
            "receipt": {
                "package_id": package["id"],
                "version": package["version"],
                "issued_at": package["issued_at"],
                "status": package["status"],
                "commitment": package["commitment"],
                "integrity": {
                    "valid": commitment_valid and signature_valid,
                    "commitment_valid": commitment_valid,
                    "local_signature_valid": signature_valid,
                    "signing_method": package["signing_method"],
                },
            },
            "access_examples": [
                {
                    "recipient": "Building owner",
                    "duration": "Persistent access",
                    "purpose": "Operation, maintenance and future alterations",
                },
                {
                    "recipient": "Future contractor",
                    "duration": "Time-limited access",
                    "purpose": "Planning an approved alteration",
                },
                {
                    "recipient": "Competent authority",
                    "duration": "Case-limited access",
                    "purpose": "Inspection under a valid legal basis",
                },
            ],
            "midnight": {
                "status": midnight_status,
                "label": {
                    "not_submitted": "Not anchored",
                    "queued": "Queued for anchoring",
                    "proving": "Generating proof",
                    "failed": "Anchoring retry scheduled",
                    "confirmed": "Anchored and confirmed",
                    "revocation_queued": "Revocation queued",
                    "revocation_pending": "Revocation pending",
                    "revocation_failed": "Revocation retry scheduled",
                    "revoked": "Anchored and revoked",
                }.get(midnight_status, "Not anchored"),
                "network": midnight["network"],
                "contract_address": midnight["contract_address"],
                "transaction": midnight["transaction"],
                "revocation_transaction": midnight["revocation_transaction"],
                "statement": midnight["statement"],
            },
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/midnight-demo/access")
@login_required
def midnight_demo_access():
    user = current_user()
    with db() as connection:
        package = demo_document_package_row(connection)
        result = demo_document_access_state(connection, package["id"], user["id"])
    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/midnight-demo/access/<recipient_key>")
@login_required
def grant_midnight_demo_access(recipient_key: str):
    user = current_user()
    preset = DEMO_ACCESS_PRESETS.get(recipient_key)
    if not preset:
        abort(404)
    timestamp = now_iso()
    expires_at = ""
    if preset["duration_days"] is not None:
        expires_at = (datetime.now(UTC) + timedelta(days=preset["duration_days"])).isoformat()
    with db() as connection:
        package = demo_document_package_row(connection)
        connection.execute(
            """
            INSERT INTO demo_document_access_grants
                (id, package_id, user_id, recipient_key, status, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
            ON CONFLICT(package_id, user_id, recipient_key) DO UPDATE SET
                status = 'active',
                expires_at = excluded.expires_at,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            """,
            (new_id("dgr"), package["id"], user["id"], recipient_key, expires_at, timestamp, timestamp),
        )
        result = demo_document_access_state(connection, package["id"], user["id"])
    return jsonify({"ok": True, **result}), 201


@app.post("/api/midnight-demo/access/<recipient_key>/revoke")
@login_required
def revoke_midnight_demo_access(recipient_key: str):
    user = current_user()
    if recipient_key not in DEMO_ACCESS_PRESETS:
        abort(404)
    timestamp = now_iso()
    with db() as connection:
        package = demo_document_package_row(connection)
        grant = connection.execute(
            """
            SELECT id FROM demo_document_access_grants
            WHERE package_id = ? AND user_id = ? AND recipient_key = ?
            """,
            (package["id"], user["id"], recipient_key),
        ).fetchone()
        if not grant:
            abort(404)
        connection.execute(
            "UPDATE demo_document_access_grants SET status = 'revoked', updated_at = ? WHERE id = ?",
            (timestamp, grant["id"]),
        )
        result = demo_document_access_state(connection, package["id"], user["id"])
    return jsonify({"ok": True, **result})


@app.get("/api/bootstrap")
@login_required
def bootstrap():
    user = current_user()
    with db() as connection:
        claim_invitations(connection, user)
        memberships = connection.execute(
            "SELECT m.*, o.name AS organization_name, o.organization_type, o.profile_json AS organization_profile_json FROM memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = ? AND m.status = 'active' ORDER BY o.name",
            (user["id"],),
        ).fetchall()
        rows = connection.execute("SELECT a.*, o.name AS organization_name FROM assignments a JOIN organizations o ON o.id = a.organization_id ORDER BY a.updated_at DESC").fetchall()
        assignments = []
        for row in rows:
            if can_access_assignment(connection, row, user):
                item = serialize_assignment_for(connection, row)
                item["organization_name"] = row["organization_name"]
                item["user_roles"] = sorted(user_assignment_roles(connection, row["id"], user))
                assignments.append(item)
        package_rows = connection.execute(
            """
            SELECT p.*, a.title AS assignment_title, a.provider_id, o.name AS organization_name,
                   u.display_name AS issued_by_name
            FROM document_packages p
            JOIN assignments a ON a.id = p.assignment_id
            JOIN organizations o ON o.id = p.organization_id
            JOIN users u ON u.id = p.created_by
            ORDER BY p.issued_at DESC
            """
        ).fetchall()
        document_packages = [
            serialize_document_package(connection, row, user)
            for row in package_rows
            if can_view_document_package(connection, row, user)
        ]
        profile = parse_json(user["profile_json"], {})
        return jsonify(
            {
                "user": {"id": user["id"], "email": user["email"], "name": user["display_name"], "profile": profile},
                "memberships": [
                    {
                        **dict(row),
                        "roles": parse_json(row["roles_json"], []),
                        "organization_profile": parse_json(row["organization_profile_json"], {}),
                    }
                    for row in memberships
                ],
                "assignments": assignments,
                "document_packages": document_packages,
                "csrf": csrf_token(),
                "policy": {key: load_policy()[key] for key in ("id", "version", "status", "notice")},
            }
        )


@app.put("/api/profile")
@login_required
def update_profile():
    user = current_user()
    payload = json_payload()
    display_name = str(payload.get("display_name", user["display_name"])).strip()[:120]
    if len(display_name) < 2:
        abort(400, "Navn må inneholde minst to tegn")
    profile = {
        "role_title": str(payload.get("role_title", ""))[:120].strip(),
        "primary_family": str(payload.get("primary_family", ""))[:30].strip(),
        "phone": str(payload.get("phone", ""))[:80].strip(),
    }
    with db() as connection:
        timestamp = now_iso()
        connection.execute(
            "UPDATE users SET display_name = ?, profile_json = ?, updated_at = ? WHERE id = ?",
            (display_name, json.dumps(profile), timestamp, user["id"]),
        )
        audit(connection, "profile.updated", user["id"], detail={"display_name": display_name})
    return jsonify({"ok": True, "name": display_name, "profile": profile})


@app.post("/api/organizations")
@login_required
def create_organization():
    user = current_user()
    payload = json_payload()
    name = str(payload.get("name", "")).strip()[:160]
    organization_type = str(payload.get("organization_type", "school")).strip()
    if len(name) < 2 or organization_type not in {"school", "enterprise", "other"}:
        abort(400, "Organisasjonsnavn eller organisasjonstype er ugyldig")
    organization_id = new_id("org")
    timestamp = now_iso()
    with db() as connection:
        connection.execute(
            "INSERT INTO organizations (id, name, organization_type, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (organization_id, name, organization_type, user["id"], timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO memberships (id, organization_id, email, user_id, roles_json, status, invited_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)",
            (new_id("mem"), organization_id, normalize_email(user["email"]), user["id"], json.dumps(["admin", "task_provider", "reviewer"]), user["id"], timestamp, timestamp),
        )
        audit(connection, "organization.created", user["id"], organization_id, detail={"organization_type": organization_type})
    return jsonify({"ok": True, "organization_id": organization_id}), 201


@app.put("/api/organizations/<organization_id>")
@login_required
def update_organization(organization_id: str):
    user = current_user()
    payload = json_payload()
    name = str(payload.get("name", "")).strip()[:160]
    organization_type = str(payload.get("organization_type", "school")).strip()
    if len(name) < 2 or organization_type not in {"school", "enterprise", "other"}:
        abort(400, "Organisasjonsnavn eller organisasjonstype er ugyldig")
    profile = {
        "organization_number": str(payload.get("organization_number", "")).strip()[:40],
        "address": str(payload.get("address", "")).strip()[:300],
        "contact_email": normalize_email(payload.get("contact_email", ""))[:200],
        "phone": str(payload.get("phone", "")).strip()[:80],
    }
    if profile["contact_email"] and "@" not in profile["contact_email"]:
        abort(400, "Kontakt-e-post er ugyldig")
    timestamp = now_iso()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin"})
        updated = connection.execute(
            "UPDATE organizations SET name = ?, organization_type = ?, profile_json = ?, updated_at = ? WHERE id = ?",
            (name, organization_type, json.dumps(profile), timestamp, organization_id),
        )
        if not updated.rowcount:
            abort(404)
        audit(connection, "organization.updated", user["id"], organization_id, detail={"name": name, "organization_type": organization_type})
    return jsonify(
        {
            "ok": True,
            "organization": {
                "id": organization_id,
                "name": name,
                "organization_type": organization_type,
                "profile": profile,
                "updated_at": timestamp,
            },
        }
    )


@app.post("/api/organizations/<organization_id>/join-links")
@login_required
def create_organization_join_link(organization_id: str):
    user = current_user()
    payload = json_payload()
    try:
        duration_days = max(1, min(30, int(payload.get("duration_days", 7))))
    except (TypeError, ValueError):
        abort(400, "Ugyldig varighet")
    token: <REDACTED>
    link_id = new_id("jnl")
    timestamp = now_iso()
    expires_at = (datetime.now(UTC) + timedelta(days=duration_days)).isoformat()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin"})
        if not connection.execute("SELECT 1 FROM organizations WHERE id = ?", (organization_id,)).fetchone():
            abort(404)
        connection.execute(
            "UPDATE organization_join_links SET status = 'revoked', updated_at = ? WHERE organization_id = ? AND status = 'active'",
            (timestamp, organization_id),
        )
        connection.execute(
            """INSERT INTO organization_join_links
               (id, organization_id, token_hash, status, created_by, expires_at, accepted_count, last_accepted_at, created_at, updated_at)
               VALUES (?, ?, ?, 'active', ?, ?, 0, '', ?, ?)""",
            (link_id, organization_id, join_token_hash(token), user["id"], expires_at, timestamp, timestamp),
        )
        audit(
            connection, "organization.join_link.created", user["id"], organization_id,
            detail={"join_link_id": link_id, "expires_at": expires_at},
        )
    join_url = url_for("join_organization", token: <REDACTED>
    return jsonify(
        {
            "ok": True,
            "join_link": {
                "id": link_id,
                "url": join_url,
                "expires_at": expires_at,
                "accepted_count": 0,
                "qr_data_url": qr_data_url(join_url),
            },
        }
    ), 201


@app.delete("/api/organizations/<organization_id>/join-links/<link_id>")
@login_required
def revoke_organization_join_link(organization_id: str, link_id: str):
    user = current_user()
    timestamp = now_iso()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin"})
        updated = connection.execute(
            "UPDATE organization_join_links SET status = 'revoked', updated_at = ? WHERE id = ? AND organization_id = ? AND status = 'active'",
            (timestamp, link_id, organization_id),
        )
        if not updated.rowcount:
            abort(404)
        audit(
            connection, "organization.join_link.revoked", user["id"], organization_id,
            detail={"join_link_id": link_id},
        )
    return jsonify({"ok": True})


@app.get("/api/organizations/<organization_id>/members")
@login_required
def list_members(organization_id: str):
    user = current_user()
    with db() as connection:
        requester_roles = require_org_role(connection, organization_id, user["id"], {"admin", "task_provider", "reviewer", "worker", "member"})
        can_inspect = bool(requester_roles.intersection({"admin", "task_provider"}))
        rows = connection.execute(
            "SELECT m.*, u.display_name, u.profile_json AS user_profile_json FROM memberships m LEFT JOIN users u ON u.id = m.user_id WHERE organization_id = ? ORDER BY lower(COALESCE(u.display_name, m.email))",
            (organization_id,),
        ).fetchall()
        members = []
        for row in rows:
            profile = parse_json(row["user_profile_json"], {}) if row["user_id"] else {}
            row_data = dict(row)
            row_data.pop("user_profile_json", None)
            row_data.pop("roles_json", None)
            member = {
                **row_data,
                "roles": parse_json(row["roles_json"], []),
                "profile": {
                    "role_title": profile.get("role_title", ""),
                    "primary_family": profile.get("primary_family", ""),
                },
                "can_inspect": can_inspect,
                "assignments": [],
                "assignment_count": 0,
                "evidence_count": 0,
                "document_count": 0,
            }
            if can_inspect and row["user_id"]:
                assignment_rows = connection.execute(
                    """
                    SELECT DISTINCT a.id, a.title, a.status, a.location_context, a.customer_id,
                           a.created_at, a.updated_at,
                           (SELECT count(*) FROM assignment_evidence e WHERE e.assignment_id = a.id AND e.created_by = ?) AS evidence_count,
                           (SELECT count(*) FROM document_packages p WHERE p.assignment_id = a.id) AS document_count
                    FROM assignments a
                    LEFT JOIN assignment_roles ar ON ar.assignment_id = a.id
                    WHERE a.organization_id = ?
                      AND (a.provider_id = ? OR ar.user_id = ? OR lower(ar.email) = ?)
                    ORDER BY a.updated_at DESC
                    """,
                    (row["user_id"], organization_id, row["user_id"], row["user_id"], normalize_email(row["email"])),
                ).fetchall()
                member["assignments"] = [dict(assignment) for assignment in assignment_rows]
                member["assignment_count"] = len(assignment_rows)
                member["evidence_count"] = sum(assignment["evidence_count"] for assignment in assignment_rows)
                member["document_count"] = sum(assignment["document_count"] for assignment in assignment_rows)
            members.append(member)
        return jsonify({"members": members, "can_inspect": can_inspect})


@app.put("/api/organizations/<organization_id>/members/<membership_id>")
@login_required
def update_member_roles(organization_id: str, membership_id: str):
    user = current_user()
    payload = json_payload()
    requested = payload.get("roles") if isinstance(payload.get("roles"), list) else []
    roles = sorted(set(str(value) for value in requested).intersection({"admin", "task_provider", "worker", "reviewer"}))
    stored_roles = roles or ["member"]
    timestamp = now_iso()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin"})
        membership = connection.execute(
            "SELECT * FROM memberships WHERE id = ? AND organization_id = ? AND status = 'active'",
            (membership_id, organization_id),
        ).fetchone()
        if not membership:
            abort(404)
        previous_roles = set(parse_json(membership["roles_json"], []))
        if "admin" in previous_roles and "admin" not in roles:
            other_admin = connection.execute(
                """SELECT 1 FROM memberships
                   WHERE organization_id = ? AND id <> ? AND status = 'active'
                     AND EXISTS (SELECT 1 FROM json_each(memberships.roles_json) WHERE value = 'admin')
                   LIMIT 1""",
                (organization_id, membership_id),
            ).fetchone()
            if not other_admin:
                abort(409, "Organisasjonen må ha minst én administrator")
        connection.execute(
            "UPDATE memberships SET roles_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(stored_roles), timestamp, membership_id),
        )
        audit(
            connection, "membership.roles.updated", user["id"], organization_id,
            detail={"membership_id": membership_id, "roles": stored_roles},
        )
    return jsonify({"ok": True, "membership_id": membership_id, "roles": stored_roles})


@app.post("/api/organizations/<organization_id>/members")
@login_required
def invite_member(organization_id: str):
    user = current_user()
    payload = json_payload()
    email = normalize_email(payload.get("email", ""))
    if "@" not in email:
        abort(400, "En gyldig e-postadresse er påkrevd")
    roles = ["member"]
    timestamp = now_iso()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin"})
        invited_user = connection.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
        connection.execute(
            """INSERT INTO memberships (id, organization_id, email, user_id, roles_json, status, invited_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, email) DO UPDATE SET roles_json = excluded.roles_json, user_id = COALESCE(memberships.user_id, excluded.user_id), status = CASE WHEN COALESCE(memberships.user_id, excluded.user_id) IS NULL THEN 'invited' ELSE 'active' END, updated_at = excluded.updated_at""",
            (new_id("mem"), organization_id, email, invited_user["id"] if invited_user else None, json.dumps(roles), "active" if invited_user else "invited", user["id"], timestamp, timestamp),
        )
        audit(connection, "membership.invited", user["id"], organization_id, detail={"email": email, "roles": roles})
    return jsonify({"ok": True, "email": email, "roles": roles}), 201


@app.get("/api/organizations/<organization_id>/customers")
@login_required
def list_customers(organization_id: str):
    user = current_user()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin", "task_provider", "reviewer", "worker"})
        rows = connection.execute(
            "SELECT id, name, address, contact_name, contact_email FROM customers WHERE organization_id = ? ORDER BY lower(name), lower(address)",
            (organization_id,),
        ).fetchall()
        return jsonify({"customers": [dict(row) for row in rows]})


@app.post("/api/assignments")
@login_required
def create_assignment():
    user = current_user()
    payload = json_payload()
    organization_id = str(payload.get("organization_id", ""))
    title = str(payload.get("title", "")).strip()[:180]
    purpose = str(payload.get("purpose", "")).strip()[:2000]
    desired_result = str(payload.get("desired_result", "")).strip()[:2000] or purpose
    families = sorted(set(payload.get("work_families") or []).intersection({"electro", "ekom"}))
    execution_context = str(payload.get("execution_context", "")).strip()
    assignees = sorted({normalize_email(value) for value in payload.get("assignees", []) if normalize_email(value)})
    reviewers = sorted({normalize_email(value) for value in payload.get("reviewers", []) if normalize_email(value)})
    if not organization_id or len(title) < 3 or not purpose or not families:
        abort(400, "Organisasjon, tittel, formål og fagområde er påkrevd")
    reviewers = reviewers or [normalize_email(user["email"])]
    assignment_id = new_id("asg")
    timestamp = now_iso()
    with db() as connection:
        require_org_role(connection, organization_id, user["id"], {"admin", "task_provider"})
        organization = connection.execute("SELECT organization_type FROM organizations WHERE id = ?", (organization_id,)).fetchone()
        if not organization:
            abort(404)
        execution_context = execution_context or ("supervised_practice" if organization["organization_type"] == "school" else "professional_work")
        if execution_context not in {"training_synthetic", "supervised_practice", "professional_work"}:
            abort(400, "Ugyldig utførelseskontekst")

        member_rows = []
        if assignees:
            placeholders = ",".join("?" for _ in assignees)
            member_rows = connection.execute(
                f"""SELECT lower(m.email) AS email, m.user_id, u.display_name
                    FROM memberships m
                    LEFT JOIN users u ON u.id = m.user_id
                    WHERE m.organization_id = ? AND m.status IN ('active', 'invited')
                      AND lower(m.email) IN ({placeholders})""",
                (organization_id, *assignees),
            ).fetchall()
        members_by_email = {row["email"]: row for row in member_rows}
        if any(email not in members_by_email for email in assignees):
            abort(400, "Tildelt person må være medlem av organisasjonen")
        responsible_member = members_by_email[assignees[0]] if assignees else None
        professional_responsible = (responsible_member["display_name"] or assignees[0]) if responsible_member else ""

        location_context = str(payload.get("location_context", "")).strip()[:1000]
        customer_id = str(payload.get("customer_id", "")).strip()
        new_customer = payload.get("new_customer") if isinstance(payload.get("new_customer"), dict) else {}
        customer_name = str(new_customer.get("name", "")).strip()[:180]
        customer_address = str(new_customer.get("address", "")).strip()[:300]
        customer = None
        if customer_id:
            customer = connection.execute(
                "SELECT * FROM customers WHERE id = ? AND organization_id = ?",
                (customer_id, organization_id),
            ).fetchone()
            if not customer:
                abort(400, "Valgt kunde eller anlegg finnes ikke i organisasjonen")
        elif customer_name:
            customer = connection.execute(
                "SELECT * FROM customers WHERE organization_id = ? AND lower(name) = lower(?) AND lower(address) = lower(?)",
                (organization_id, customer_name, customer_address),
            ).fetchone()
            if not customer:
                customer_id = new_id("cus")
                connection.execute(
                    "INSERT INTO customers (id, organization_id, name, address, contact_name, contact_email, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, '', '', ?, ?, ?)",
                    (customer_id, organization_id, customer_name, customer_address, user["id"], timestamp, timestamp),
                )
                customer = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
                audit(connection, "customer.created", user["id"], organization_id, detail={"customer_id": customer_id})
        if customer:
            location_context = customer_location(customer)
        if not location_context:
            abort(400, "Kunde eller anlegg er påkrevd")

        connection.execute(
            """INSERT INTO assignments (id, organization_id, title, purpose, desired_result, known_scope, known_constraints, location_context, execution_context, customer_id, due_at, expected_submission, work_families_json, provider_id, professional_responsible, version, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'published', ?, ?)""",
            (
                assignment_id,
                organization_id,
                title,
                purpose,
                desired_result,
                str(payload.get("known_scope", "")).strip()[:4000],
                str(payload.get("known_constraints", "")).strip()[:4000],
                location_context,
                execution_context,
                customer["id"] if customer else "",
                "",
                str(payload.get("expected_submission", "Plan med arbeidsmetode, risiko, kontroll og dokumentasjon"))[:2000],
                json.dumps(families),
                user["id"],
                professional_responsible[:300],
                timestamp,
                timestamp,
            ),
        )
        role_map = {
            "task_provider": [normalize_email(user["email"])],
            "assigned_worker": assignees,
            "professional_responsible": assignees[:1],
            "reviewer": reviewers,
        }
        for role, emails in role_map.items():
            for email in emails:
                linked = connection.execute("SELECT id FROM users WHERE lower(email) = ?", (email,)).fetchone()
                connection.execute(
                    "INSERT INTO assignment_roles (id, assignment_id, role, email, user_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (new_id("rol"), assignment_id, role, email, linked["id"] if linked else None, "assigned" if linked else "invited", timestamp, timestamp),
                )
        audit(connection, "assignment.published", user["id"], organization_id, assignment_id, {"version": 1, "families": families, "execution_context": execution_context, "customer_id": customer["id"] if customer else "", "available": not assignees})
    return jsonify({"ok": True, "assignment_id": assignment_id}), 201


@app.put("/api/assignments/<assignment_id>")
@login_required
def update_assignment(assignment_id: str):
    user = current_user()
    payload = json_payload()
    title = str(payload.get("title", "")).strip()[:180]
    purpose = str(payload.get("purpose", "")).strip()[:2000]
    families = sorted(set(payload.get("work_families") or []).intersection({"electro", "ekom"}))
    if len(title) < 3 or not purpose or not families:
        abort(400, "Tittel, formål og fagområde er påkrevd")
    timestamp = now_iso()
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        assignment = assignment_row(connection, assignment_id)
        require_org_role(connection, assignment["organization_id"], user["id"], {"admin", "task_provider"})
        if assignment["status"] != "published":
            abort(409, "Oppdraget kan bare redigeres før arbeidet er startet")
        if assignment_has_artifacts(connection, assignment_id):
            abort(409, "Oppdraget har arbeidsdata eller dokumentasjon og kan ikke redigeres direkte")

        customer_id = str(payload.get("customer_id", "")).strip()
        new_customer = payload.get("new_customer") if isinstance(payload.get("new_customer"), dict) else {}
        customer_name = str(new_customer.get("name", "")).strip()[:180]
        customer_address = str(new_customer.get("address", "")).strip()[:300]
        customer = None
        if customer_id:
            customer = connection.execute(
                "SELECT * FROM customers WHERE id = ? AND organization_id = ?",
                (customer_id, assignment["organization_id"]),
            ).fetchone()
            if not customer:
                abort(400, "Valgt kunde eller anlegg finnes ikke i organisasjonen")
        elif customer_name:
            customer = connection.execute(
                "SELECT * FROM customers WHERE organization_id = ? AND lower(name) = lower(?) AND lower(address) = lower(?)",
                (assignment["organization_id"], customer_name, customer_address),
            ).fetchone()
            if not customer:
                customer_id = new_id("cus")
                connection.execute(
                    "INSERT INTO customers (id, organization_id, name, address, contact_name, contact_email, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, '', '', ?, ?, ?)",
                    (customer_id, assignment["organization_id"], customer_name, customer_address, user["id"], timestamp, timestamp),
                )
                customer = connection.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
                audit(connection, "customer.created", user["id"], assignment["organization_id"], detail={"customer_id": customer_id})
        if not customer:
            abort(400, "Kunde eller anlegg er påkrevd")

        new_version = int(assignment["version"]) + 1
        connection.execute(
            """UPDATE assignments
               SET title = ?, purpose = ?, desired_result = ?, known_scope = ?, known_constraints = ?,
                   location_context = ?, customer_id = ?, work_families_json = ?, version = ?, updated_at = ?
               WHERE id = ?""",
            (
                title,
                purpose,
                purpose,
                str(payload.get("known_scope", "")).strip()[:4000],
                str(payload.get("known_constraints", "")).strip()[:4000],
                customer_location(customer),
                customer["id"],
                json.dumps(families),
                new_version,
                timestamp,
                assignment_id,
            ),
        )
        audit(
            connection,
            "assignment.updated",
            user["id"],
            assignment["organization_id"],
            assignment_id,
            {"version": new_version, "families": families, "customer_id": customer["id"]},
        )
    return jsonify({"ok": True, "assignment_id": assignment_id, "version": new_version})


@app.delete("/api/assignments/<assignment_id>")
@login_required
def delete_assignment(assignment_id: str):
    user = current_user()
    timestamp = now_iso()
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        assignment = assignment_row(connection, assignment_id)
        require_org_role(connection, assignment["organization_id"], user["id"], {"admin", "task_provider"})
        if assignment["status"] != "published":
            abort(409, "Oppdraget kan bare slettes før arbeidet er startet")
        if assignment_has_artifacts(connection, assignment_id):
            abort(409, "Oppdraget har arbeidsdata eller dokumentasjon og kan ikke slettes")
        connection.execute("UPDATE assignments SET status = 'cancelled', updated_at = ? WHERE id = ?", (timestamp, assignment_id))
        connection.execute("UPDATE assignment_roles SET status = 'cancelled', updated_at = ? WHERE assignment_id = ?", (timestamp, assignment_id))
        audit(connection, "assignment.deleted", user["id"], assignment["organization_id"], assignment_id, {"version": assignment["version"]})
    return jsonify({"ok": True, "assignment_id": assignment_id, "deleted": True})


@app.get("/api/assignments/<assignment_id>")
@login_required
def get_assignment(assignment_id: str):
    user = current_user()
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        if not can_access_assignment(connection, assignment, user):
            abort(403)
        own_roles = user_assignment_roles(connection, assignment_id, user)
        draft_row = connection.execute(
            "SELECT data_json, updated_at FROM planning_drafts WHERE assignment_id = ? AND user_id = ?",
            (assignment_id, user["id"]),
        ).fetchone()
        draft = parse_json(draft_row["data_json"], {}) if draft_row else {}
        completion_draft_row = connection.execute(
            "SELECT data_json, updated_at FROM completion_drafts WHERE assignment_id = ? AND user_id = ?",
            (assignment_id, user["id"]),
        ).fetchone()
        completion_draft = parse_json(completion_draft_row["data_json"], {}) if completion_draft_row else {}
        can_view_submissions = bool(own_roles.intersection({"assigned_worker", "reviewer", "task_provider"}) or assignment["provider_id"] == user["id"] or membership_roles(connection, assignment["organization_id"], user["id"]).intersection({"admin", "task_provider"}))
        return jsonify(
            {
                "assignment": serialize_assignment_for(connection, assignment),
                "roles": assignment_roles(connection, assignment_id),
                "user_roles": sorted(own_roles),
                "draft": draft,
                "draft_updated_at": draft_row["updated_at"] if draft_row else "",
                "completion_draft": completion_draft,
                "completion_draft_updated_at": completion_draft_row["updated_at"] if completion_draft_row else "",
                "considerations": considerations_for(assignment, draft),
                "submissions": submissions_for(connection, assignment_id) if can_view_submissions else [],
                "completion_submissions": completion_submissions_for(connection, assignment_id) if can_view_submissions else [],
                "evidence": [serialize_evidence(row) for row in evidence_rows_for(connection, assignment_id)],
                "document_packages": document_packages_for_assignment(connection, assignment_id, user),
                "policy": {key: load_policy()[key] for key in ("version", "status", "notice")},
            }
        )


@app.post("/api/assignments/<assignment_id>/evidence")
@login_required
def register_assignment_evidence(assignment_id: str):
    user = current_user()
    phase = str(request.form.get("phase", "")).strip()
    evidence_type = str(request.form.get("evidence_type", "")).strip()
    title = str(request.form.get("title", "")).strip()[:180]
    note = str(request.form.get("note", "")).strip()[:4000]
    if phase not in {"before", "during", "after"}:
        abort(400, "Velg om dokumentasjonen gjelder før, under eller etter arbeidet")
    if evidence_type not in {"photo", "measurement", "checklist", "declaration", "product_data", "drawing", "other"}:
        abort(400, "Velg dokumentasjonstype")
    if len(title) < 2:
        abort(400, "Tittel på dokumentasjonen er påkrevd")

    upload = request.files.get("file")
    original_filename = ""
    media_type = ""
    content = b""
    suffix = ""
    if upload and upload.filename:
        original_filename = Path(str(upload.filename).replace("\\", "/")).name.replace("\x00", "")[:240]
        suffix = Path(original_filename).suffix.lower()
        if suffix not in ALLOWED_EVIDENCE_EXTENSIONS:
            abort(400, "Filtypen kan ikke lagres som dokumentasjon")
        content = upload.read(MAX_EVIDENCE_BYTES + 1)
        if len(content) > MAX_EVIDENCE_BYTES:
            abort(413, "Dokumentasjonen kan være maksimalt 10 MB")
        media_type = str(upload.mimetype or "application/octet-stream")[:160]
    if not content and not note:
        abort(400, "Legg ved en fil eller skriv en merknad")

    evidence_id = new_id("evd")
    registered_at = now_iso()
    storage_name = f"{evidence_id}{suffix}" if content else ""
    content_sha256 = hashlib.sha256(content).hexdigest()
    envelope = {
        "schema": "esense.assignment-evidence.v1",
        "id": evidence_id,
        "assignment_id": assignment_id,
        "phase": phase,
        "evidence_type": evidence_type,
        "title": title,
        "note": note,
        "original_filename": original_filename,
        "media_type": media_type,
        "byte_size": len(content),
        "content_sha256": content_sha256,
        "registered_at": registered_at,
        "registered_by": {"id": user["id"], "name": user["display_name"]},
    }
    salt = secrets.token_hex(32)
    commitment = document_commitment(envelope, salt)
    target_path = None
    try:
        with db() as connection:
            assignment = assignment_row(connection, assignment_id)
            own_roles = user_assignment_roles(connection, assignment_id, user)
            org_roles = membership_roles(connection, assignment["organization_id"], user["id"])
            if not (
                "assigned_worker" in own_roles
                or assignment["provider_id"] == user["id"]
                or org_roles.intersection({"admin", "task_provider"})
            ):
                abort(403)
            if content:
                target_dir = EVIDENCE_DIR / assignment_id
                target_dir.mkdir(parents=True, exist_ok=True)
                target_path = target_dir / storage_name
                target_path.write_bytes(content)
            connection.execute(
                """INSERT INTO assignment_evidence
                       (id, assignment_id, organization_id, created_by, phase, evidence_type, title, note,
                        original_filename, storage_name, media_type, byte_size, content_sha256,
                        commitment_salt, commitment, registered_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id, assignment_id, assignment["organization_id"], user["id"], phase,
                    evidence_type, title, note, original_filename, storage_name, media_type, len(content),
                    content_sha256, salt, commitment, registered_at, registered_at,
                ),
            )
            audit(
                connection,
                "evidence.registered",
                user["id"],
                assignment["organization_id"],
                assignment_id,
                {"evidence_id": evidence_id, "phase": phase, "content_sha256": content_sha256, "commitment": commitment},
            )
            row = connection.execute(
                """SELECT e.*, u.display_name AS registered_by_name
                   FROM assignment_evidence e JOIN users u ON u.id = e.created_by
                   WHERE e.id = ?""",
                (evidence_id,),
            ).fetchone()
            result = serialize_evidence(row)
    except Exception:
        if target_path and target_path.exists():
            target_path.unlink()
        raise
    return jsonify({"ok": True, "evidence": result}), 201


@app.get("/api/assignment-evidence/<evidence_id>/file")
@login_required
def download_assignment_evidence(evidence_id: str):
    user = current_user()
    with db() as connection:
        row = connection.execute("SELECT * FROM assignment_evidence WHERE id = ?", (evidence_id,)).fetchone()
        if not row or not row["storage_name"]:
            abort(404)
        assignment = assignment_row(connection, row["assignment_id"])
        allowed = can_access_assignment(connection, assignment, user)
        if not allowed:
            package_rows = connection.execute(
                """SELECT p.*, a.title AS assignment_title, a.provider_id, o.name AS organization_name,
                          u.display_name AS issued_by_name
                   FROM document_packages p
                   JOIN assignments a ON a.id = p.assignment_id
                   JOIN organizations o ON o.id = p.organization_id
                   JOIN users u ON u.id = p.created_by
                   WHERE p.assignment_id = ? AND p.status != 'revoked'""",
                (row["assignment_id"],),
            ).fetchall()
            for package in package_rows:
                if not can_view_document_package(connection, package, user):
                    continue
                try:
                    manifest = decrypt_document_manifest(package["manifest_json"], package["id"])
                except (InvalidTag, KeyError, ValueError):
                    continue
                if any(item.get("id") == evidence_id for item in manifest.get("evidence_timeline", [])):
                    allowed = True
                    break
        if not allowed:
            abort(403)
        path = EVIDENCE_DIR / row["assignment_id"] / row["storage_name"]
        if not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=row["original_filename"], mimetype=row["media_type"] or None)


@app.post("/api/assignments/<assignment_id>/action")
@login_required
def assignment_action(assignment_id: str):
    user = current_user()
    payload = json_payload()
    action = str(payload.get("action", ""))
    if action not in {"accept", "decline", "request_clarification"}:
        abort(400)
    timestamp = now_iso()
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        if "assigned_worker" not in user_assignment_roles(connection, assignment_id, user):
            abort(403)
        status = {"accept": "accepted", "decline": "declined", "request_clarification": "published"}[action]
        role_status = {"accept": "accepted", "decline": "declined", "request_clarification": "clarification_requested"}[action]
        connection.execute("UPDATE assignments SET status = ?, updated_at = ? WHERE id = ?", (status, timestamp, assignment_id))
        connection.execute("UPDATE assignment_roles SET status = ?, updated_at = ? WHERE assignment_id = ? AND role = 'assigned_worker' AND user_id = ?", (role_status, timestamp, assignment_id, user["id"]))
        audit(connection, f"assignment.{action}", user["id"], assignment["organization_id"], assignment_id, {"message": str(payload.get("message", ""))[:1000]})
    return jsonify({"ok": True, "status": status})


@app.post("/api/assignments/<assignment_id>/claim")
@login_required
def claim_assignment(assignment_id: str):
    user = current_user()
    timestamp = now_iso()
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        assignment = assignment_row(connection, assignment_id)
        require_org_role(connection, assignment["organization_id"], user["id"], {"worker"})
        if assignment["status"] != "published":
            abort(409, "Oppdraget er ikke lenger tilgjengelig")
        if assigned_worker_role(connection, assignment_id):
            abort(409, "Oppdraget er allerede tildelt")
        email = normalize_email(user["email"])
        connection.execute(
            "INSERT INTO assignment_roles (id, assignment_id, role, email, user_id, status, created_at, updated_at) VALUES (?, ?, 'assigned_worker', ?, ?, 'accepted', ?, ?)",
            (new_id("rol"), assignment_id, email, user["id"], timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO assignment_roles (id, assignment_id, role, email, user_id, status, created_at, updated_at) VALUES (?, ?, 'professional_responsible', ?, ?, 'accepted', ?, ?)",
            (new_id("rol"), assignment_id, email, user["id"], timestamp, timestamp),
        )
        connection.execute(
            "UPDATE assignments SET professional_responsible = ?, status = 'accepted', updated_at = ? WHERE id = ?",
            ((user["display_name"] or email)[:300], timestamp, assignment_id),
        )
        audit(connection, "assignment.claimed", user["id"], assignment["organization_id"], assignment_id, {"assigned_at": timestamp})
    return jsonify({"ok": True, "status": "accepted"})


@app.post("/api/assignments/<assignment_id>/assign")
@login_required
def assign_available_assignment(assignment_id: str):
    user = current_user()
    payload = json_payload()
    email = normalize_email(payload.get("assignee_email", ""))
    if not email:
        abort(400, "Velg en person")
    timestamp = now_iso()
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        assignment = assignment_row(connection, assignment_id)
        require_org_role(connection, assignment["organization_id"], user["id"], {"admin", "task_provider"})
        if assignment["status"] != "published":
            abort(409, "Oppdraget kan ikke tildeles i nåværende status")
        if assigned_worker_role(connection, assignment_id):
            abort(409, "Oppdraget er allerede tildelt")
        member = connection.execute(
            """SELECT m.*, u.display_name FROM memberships m
               JOIN users u ON u.id = m.user_id
               WHERE m.organization_id = ? AND lower(m.email) = ? AND m.status = 'active'""",
            (assignment["organization_id"], email),
        ).fetchone()
        if not member or "worker" not in set(parse_json(member["roles_json"], [])):
            abort(400, "Personen må være en aktiv arbeidstaker i organisasjonen")
        connection.execute(
            "INSERT INTO assignment_roles (id, assignment_id, role, email, user_id, status, created_at, updated_at) VALUES (?, ?, 'assigned_worker', ?, ?, 'assigned', ?, ?)",
            (new_id("rol"), assignment_id, email, member["user_id"], timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO assignment_roles (id, assignment_id, role, email, user_id, status, created_at, updated_at) VALUES (?, ?, 'professional_responsible', ?, ?, 'assigned', ?, ?)",
            (new_id("rol"), assignment_id, email, member["user_id"], timestamp, timestamp),
        )
        connection.execute(
            "UPDATE assignments SET professional_responsible = ?, updated_at = ? WHERE id = ?",
            ((member["display_name"] or email)[:300], timestamp, assignment_id),
        )
        audit(connection, "assignment.assigned", user["id"], assignment["organization_id"], assignment_id, {"assignee_email": email, "assigned_at": timestamp})
    return jsonify({"ok": True, "status": "published"})


@app.put("/api/assignments/<assignment_id>/team")
@login_required
def update_assignment_team(assignment_id: str):
    user = current_user()
    payload = json_payload()
    worker_emails = sorted({
        normalize_email(value) for value in payload.get("worker_emails", [])
        if normalize_email(value)
    })
    responsible_email = normalize_email(payload.get("professional_responsible_email", ""))
    if worker_emails and (not responsible_email or responsible_email not in worker_emails):
        abort(400, "Velg én AFA blant personene i arbeidslaget")
    if not worker_emails and responsible_email:
        abort(400, "AFA må være medlem av arbeidslaget")
    timestamp = now_iso()
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        assignment = assignment_row(connection, assignment_id)
        require_org_role(connection, assignment["organization_id"], user["id"], {"admin", "task_provider"})
        if assignment["status"] in {"completed", "closed", "cancelled", "declined"}:
            abort(409, "Arbeidslaget kan ikke endres etter at oppdraget er avsluttet")

        members_by_email: dict[str, sqlite3.Row] = {}
        if worker_emails:
            placeholders = ",".join("?" for _ in worker_emails)
            members = connection.execute(
                f"""SELECT m.*, u.display_name
                    FROM memberships m
                    JOIN users u ON u.id = m.user_id
                    WHERE m.organization_id = ? AND m.status = 'active'
                      AND lower(m.email) IN ({placeholders})""",
                (assignment["organization_id"], *worker_emails),
            ).fetchall()
            members_by_email = {normalize_email(member["email"]): member for member in members}
        if any(
            email not in members_by_email
            or "worker" not in set(parse_json(members_by_email[email]["roles_json"], []))
            for email in worker_emails
        ):
            abort(400, "Alle i arbeidslaget må være aktive teknikere i organisasjonen")

        previous = {
            (row["role"], normalize_email(row["email"])): row
            for row in connection.execute(
                "SELECT * FROM assignment_roles WHERE assignment_id = ? AND role IN ('assigned_worker', 'professional_responsible')",
                (assignment_id,),
            ).fetchall()
        }
        connection.execute(
            "DELETE FROM assignment_roles WHERE assignment_id = ? AND role IN ('assigned_worker', 'professional_responsible')",
            (assignment_id,),
        )
        for email in worker_emails:
            member = members_by_email[email]
            prior = previous.get(("assigned_worker", email))
            connection.execute(
                """INSERT INTO assignment_roles
                       (id, assignment_id, role, email, user_id, status, created_at, updated_at)
                   VALUES (?, ?, 'assigned_worker', ?, ?, ?, ?, ?)""",
                (
                    new_id("rol"), assignment_id, email, member["user_id"],
                    prior["status"] if prior else "assigned",
                    prior["created_at"] if prior else timestamp,
                    timestamp,
                ),
            )
        responsible_name = ""
        if responsible_email:
            member = members_by_email[responsible_email]
            prior = previous.get(("professional_responsible", responsible_email))
            responsible_name = member["display_name"] or responsible_email
            connection.execute(
                """INSERT INTO assignment_roles
                       (id, assignment_id, role, email, user_id, status, created_at, updated_at)
                   VALUES (?, ?, 'professional_responsible', ?, ?, ?, ?, ?)""",
                (
                    new_id("rol"), assignment_id, responsible_email, member["user_id"],
                    prior["status"] if prior else "assigned",
                    prior["created_at"] if prior else timestamp,
                    timestamp,
                ),
            )
        connection.execute(
            "UPDATE assignments SET professional_responsible = ?, updated_at = ? WHERE id = ?",
            (responsible_name[:300], timestamp, assignment_id),
        )
        audit(
            connection,
            "assignment.team.updated",
            user["id"],
            assignment["organization_id"],
            assignment_id,
            {"worker_emails": worker_emails, "professional_responsible_email": responsible_email},
        )
        updated = serialize_assignment_for(connection, assignment_row(connection, assignment_id))
    return jsonify({"ok": True, "assignment": updated})


@app.put("/api/assignments/<assignment_id>/draft")
@login_required
def save_draft(assignment_id: str):
    user = current_user()
    planning = json_payload()
    timestamp = now_iso()
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        if "assigned_worker" not in user_assignment_roles(connection, assignment_id, user):
            abort(403)
        connection.execute(
            """INSERT INTO planning_drafts (id, assignment_id, user_id, data_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(assignment_id, user_id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at""",
            (new_id("drf"), assignment_id, user["id"], json.dumps(planning, separators=(",", ":")), timestamp, timestamp),
        )
        if assignment["status"] not in {"submitted", "accepted_plan", "cancelled", "closed"}:
            connection.execute("UPDATE assignments SET status = 'in_planning', updated_at = ? WHERE id = ?", (timestamp, assignment_id))
        audit(connection, "planning.saved", user["id"], assignment["organization_id"], assignment_id, {"fields": sorted(planning.keys())})
        considerations = considerations_for(assignment, planning)
    return jsonify({"ok": True, "updated_at": timestamp, "considerations": considerations})


@app.post("/api/assignments/<assignment_id>/submit")
@login_required
def submit_plan(assignment_id: str):
    user = current_user()
    timestamp = now_iso()
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        if "assigned_worker" not in user_assignment_roles(connection, assignment_id, user):
            abort(403)
        draft_row = connection.execute("SELECT data_json FROM planning_drafts WHERE assignment_id = ? AND user_id = ?", (assignment_id, user["id"])).fetchone()
        if not draft_row:
            abort(400, "Det finnes ingen lagret arbeidskopi")
        planning = parse_json(draft_row["data_json"], {})
        required = ["work_description", "work_method", "risk_controls", "tests_and_evidence", "open_questions"]
        missing = [field for field in required if not str(planning.get(field, "")).strip()]
        if missing:
            return jsonify({"ok": False, "missing": missing}), 400
        version_row = connection.execute("SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM submissions WHERE assignment_id = ? AND submitted_by = ?", (assignment_id, user["id"])).fetchone()
        version = int(version_row["next_version"])
        snapshot = {
            "assignment": serialize_assignment(assignment),
            "planning": planning,
            "considerations": considerations_for(assignment, planning),
            "submitted_by": {"id": user["id"], "name": user["display_name"], "email": user["email"]},
            "submitted_at": timestamp,
            "submission_version": version,
        }
        submission_id = new_id("sub")
        connection.execute(
            "INSERT INTO submissions (id, assignment_id, submitted_by, version, snapshot_json, status, submitted_at, updated_at) VALUES (?, ?, ?, ?, ?, 'submitted', ?, ?)",
            (submission_id, assignment_id, user["id"], version, json.dumps(snapshot, separators=(",", ":")), timestamp, timestamp),
        )
        connection.execute("UPDATE assignments SET status = 'submitted', updated_at = ? WHERE id = ?", (timestamp, assignment_id))
        audit(connection, "planning.submitted", user["id"], assignment["organization_id"], assignment_id, {"submission_id": submission_id, "version": version})
    return jsonify({"ok": True, "submission_id": submission_id, "version": version}), 201


@app.post("/api/submissions/<submission_id>/review")
@login_required
def review_submission(submission_id: str):
    user = current_user()
    payload = json_payload()
    decision = str(payload.get("decision", ""))
    if decision not in {"accepted", "returned"}:
        abort(400, "Beslutningen må være godkjent eller returnert")
    summary = str(payload.get("summary", "")).strip()[:4000]
    findings = payload.get("findings") or []
    if not summary or not isinstance(findings, list):
        abort(400, "Oppsummering og funn er påkrevd")
    findings = [str(value).strip()[:1000] for value in findings if str(value).strip()][:30]
    timestamp = now_iso()
    with db() as connection:
        submission = connection.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,)).fetchone()
        if not submission:
            abort(404)
        assignment = assignment_row(connection, submission["assignment_id"])
        roles = user_assignment_roles(connection, assignment["id"], user)
        org_roles = membership_roles(connection, assignment["organization_id"], user["id"])
        if not (roles.intersection({"reviewer", "task_provider"}) or assignment["provider_id"] == user["id"] or org_roles.intersection({"admin", "task_provider", "reviewer"})):
            abort(403)
        connection.execute(
            "INSERT INTO reviews (id, submission_id, reviewer_id, decision, summary, findings_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_id("rev"), submission_id, user["id"], decision, summary, json.dumps(findings), timestamp),
        )
        connection.execute("UPDATE submissions SET status = ?, updated_at = ? WHERE id = ?", (decision, timestamp, submission_id))
        assignment_status = "accepted_plan" if decision == "accepted" else "returned"
        connection.execute("UPDATE assignments SET status = ?, updated_at = ? WHERE id = ?", (assignment_status, timestamp, assignment["id"]))
        audit(connection, f"review.{decision}", user["id"], assignment["organization_id"], assignment["id"], {"submission_id": submission_id, "findings": len(findings)})
    return jsonify({"ok": True, "status": decision})


@app.put("/api/assignments/<assignment_id>/completion-draft")
@login_required
def save_completion_draft(assignment_id: str):
    user = current_user()
    completion = json_payload()
    timestamp = now_iso()
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        if "assigned_worker" not in user_assignment_roles(connection, assignment_id, user):
            abort(403)
        if assignment["status"] not in {"accepted_plan", "in_execution", "completion_returned"}:
            abort(409, "En godkjent plan må foreligge før utførelsen kan registreres")
        connection.execute(
            """INSERT INTO completion_drafts
                   (id, assignment_id, user_id, data_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(assignment_id, user_id)
               DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at""",
            (new_id("cmpd"), assignment_id, user["id"], json.dumps(completion, separators=(",", ":")), timestamp, timestamp),
        )
        connection.execute("UPDATE assignments SET status = 'in_execution', updated_at = ? WHERE id = ?", (timestamp, assignment_id))
        audit(connection, "completion.saved", user["id"], assignment["organization_id"], assignment_id, {"fields": sorted(completion.keys())})
    return jsonify({"ok": True, "updated_at": timestamp, "status": "in_execution"})


@app.post("/api/assignments/<assignment_id>/completion-submit")
@login_required
def submit_completion(assignment_id: str):
    user = current_user()
    timestamp = now_iso()
    required = ["work_performed", "safe_closure", "tests_and_results", "deviations", "evidence_references"]
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        if "assigned_worker" not in user_assignment_roles(connection, assignment_id, user):
            abort(403)
        if assignment["status"] not in {"accepted_plan", "in_execution", "completion_returned"}:
            abort(409, "Utførelsesregistreringen kan ikke sendes inn i oppdragets nåværende status")
        draft_row = connection.execute(
            "SELECT data_json FROM completion_drafts WHERE assignment_id = ? AND user_id = ?",
            (assignment_id, user["id"]),
        ).fetchone()
        if not draft_row:
            abort(400, "Det finnes ingen lagret utførelsesregistrering")
        completion = parse_json(draft_row["data_json"], {})
        missing = [field for field in required if not str(completion.get(field, "")).strip()]
        if missing:
            return jsonify({"ok": False, "missing": missing}), 400
        plan = connection.execute(
            "SELECT * FROM submissions WHERE assignment_id = ? AND status = 'accepted' ORDER BY version DESC LIMIT 1",
            (assignment_id,),
        ).fetchone()
        if not plan:
            abort(409, "Fant ingen godkjent planversjon")
        version_row = connection.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM completion_submissions WHERE assignment_id = ? AND submitted_by = ?",
            (assignment_id, user["id"]),
        ).fetchone()
        version = int(version_row["next_version"])
        snapshot = {
            "assignment": serialize_assignment(assignment),
            "accepted_plan": {"id": plan["id"], "version": plan["version"]},
            "completion": completion,
            "submitted_by": {"id": user["id"], "name": user["display_name"], "email": user["email"]},
            "submitted_at": timestamp,
            "submission_version": version,
        }
        completion_submission_id = new_id("cmps")
        connection.execute(
            """INSERT INTO completion_submissions
                   (id, assignment_id, submitted_by, version, snapshot_json, status, submitted_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'submitted', ?, ?)""",
            (completion_submission_id, assignment_id, user["id"], version, json.dumps(snapshot, separators=(",", ":")), timestamp, timestamp),
        )
        connection.execute("UPDATE assignments SET status = 'completion_submitted', updated_at = ? WHERE id = ?", (timestamp, assignment_id))
        audit(connection, "completion.submitted", user["id"], assignment["organization_id"], assignment_id, {"completion_submission_id": completion_submission_id, "version": version})
    return jsonify({"ok": True, "completion_submission_id": completion_submission_id, "version": version}), 201


@app.post("/api/completion-submissions/<completion_submission_id>/review")
@login_required
def review_completion(completion_submission_id: str):
    user = current_user()
    payload = json_payload()
    decision = str(payload.get("decision", ""))
    if decision not in {"accepted", "returned"}:
        abort(400, "Beslutningen må være godkjent eller returnert")
    summary = str(payload.get("summary", "")).strip()[:4000]
    findings = payload.get("findings") or []
    if not summary or not isinstance(findings, list):
        abort(400, "Oppsummering og funn er påkrevd")
    findings = [str(value).strip()[:1000] for value in findings if str(value).strip()][:30]
    timestamp = now_iso()
    with db() as connection:
        completion_submission = connection.execute(
            "SELECT * FROM completion_submissions WHERE id = ?",
            (completion_submission_id,),
        ).fetchone()
        if not completion_submission:
            abort(404)
        if completion_submission["status"] != "submitted":
            abort(409, "Utførelsesregistreringen er allerede vurdert")
        assignment = assignment_row(connection, completion_submission["assignment_id"])
        roles = user_assignment_roles(connection, assignment["id"], user)
        org_roles = membership_roles(connection, assignment["organization_id"], user["id"])
        if not (roles.intersection({"reviewer", "task_provider"}) or assignment["provider_id"] == user["id"] or org_roles.intersection({"admin", "task_provider", "reviewer"})):
            abort(403)
        connection.execute(
            """INSERT INTO completion_reviews
                   (id, completion_submission_id, reviewer_id, decision, summary, findings_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (new_id("cmpr"), completion_submission_id, user["id"], decision, summary, json.dumps(findings), timestamp),
        )
        connection.execute(
            "UPDATE completion_submissions SET status = ?, updated_at = ? WHERE id = ?",
            (decision, timestamp, completion_submission_id),
        )
        assignment_status = "completed" if decision == "accepted" else "completion_returned"
        connection.execute("UPDATE assignments SET status = ?, updated_at = ? WHERE id = ?", (assignment_status, timestamp, assignment["id"]))
        audit(connection, f"completion.review.{decision}", user["id"], assignment["organization_id"], assignment["id"], {"completion_submission_id": completion_submission_id, "findings": len(findings)})
    return jsonify({"ok": True, "status": decision})


@app.get("/api/document-packages")
@login_required
def list_document_packages():
    user = current_user()
    organization_id = str(request.args.get("organization_id", "")).strip()
    with db() as connection:
        rows = connection.execute(
            """
            SELECT p.*, a.title AS assignment_title, a.provider_id, o.name AS organization_name,
                   u.display_name AS issued_by_name
            FROM document_packages p
            JOIN assignments a ON a.id = p.assignment_id
            JOIN organizations o ON o.id = p.organization_id
            JOIN users u ON u.id = p.created_by
            WHERE (? = '' OR p.organization_id = ?)
            ORDER BY p.issued_at DESC
            """,
            (organization_id, organization_id),
        ).fetchall()
        packages = [
            serialize_document_package(connection, row, user)
            for row in rows
            if can_view_document_package(connection, row, user)
        ]
    return jsonify({"document_packages": packages})


@app.post("/api/assignments/<assignment_id>/document-packages")
@login_required
def issue_document_package(assignment_id: str):
    user = current_user()
    payload = json_payload()
    owner_email = normalize_email(payload.get("owner_email", ""))
    property_reference = str(payload.get("property_reference", "")).strip()[:300]
    title = str(payload.get("title", "")).strip()[:180]
    purpose = str(payload.get("purpose", "Varig dokumentasjon for eier av anlegget")).strip()[:1000]
    if "@" not in owner_email or len(property_reference) < 3:
        abort(400, "Anleggsreferanse og eier eller dokumentmottaker er påkrevd")

    timestamp = now_iso()
    package_id = new_id("pkg")
    with db() as connection:
        assignment = assignment_row(connection, assignment_id)
        org_roles = membership_roles(connection, assignment["organization_id"], user["id"])
        if assignment["provider_id"] != user["id"] and not org_roles.intersection({"admin", "task_provider"}):
            abort(403)
        if assignment["status"] != "completed":
            abort(409, "Godkjent utførelse og sluttkontroll må foreligge før dokumentasjonspakken kan utstedes")
        submission = connection.execute(
            "SELECT * FROM submissions WHERE assignment_id = ? AND status = 'accepted' ORDER BY version DESC LIMIT 1",
            (assignment_id,),
        ).fetchone()
        if not submission:
            abort(409, "Fant ingen godkjent planversjon")
        completion_submission = connection.execute(
            "SELECT * FROM completion_submissions WHERE assignment_id = ? AND status = 'accepted' ORDER BY version DESC LIMIT 1",
            (assignment_id,),
        ).fetchone()
        if not completion_submission:
            abort(409, "Fant ingen godkjent utførelsesregistrering")
        completion_snapshot = parse_json(completion_submission["snapshot_json"], {})
        completion = completion_snapshot.get("completion", {})
        summary = str(completion.get("work_performed", "")).strip()[:6000]
        tests_and_results = str(completion.get("tests_and_results", "")).strip()[:6000]
        deviations = str(completion.get("deviations", "")).strip()[:4000]
        handover_notes = str(completion.get("handover_notes", "")).strip()[:4000]
        evidence_references = str(completion.get("evidence_references", "")).strip()[:4000]
        safe_closure = str(completion.get("safe_closure", "")).strip()[:4000]
        if len(summary) < 10 or not tests_and_results:
            abort(409, "Den godkjente utførelsesregistreringen mangler arbeid eller kontrollresultater")
        reviews = connection.execute(
            """
            SELECT r.decision, r.summary, r.findings_json, r.created_at, u.display_name AS reviewer_name
            FROM reviews r JOIN users u ON u.id = r.reviewer_id
            WHERE r.submission_id = ? ORDER BY r.created_at
            """,
            (submission["id"],),
        ).fetchall()
        completion_reviews = connection.execute(
            """SELECT r.decision, r.summary, r.findings_json, r.created_at, u.display_name AS reviewer_name
               FROM completion_reviews r JOIN users u ON u.id = r.reviewer_id
               WHERE r.completion_submission_id = ? ORDER BY r.created_at""",
            (completion_submission["id"],),
        ).fetchall()
        version_row = connection.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM document_packages WHERE assignment_id = ?",
            (assignment_id,),
        ).fetchone()
        version = int(version_row["next_version"])
        organization = connection.execute("SELECT name FROM organizations WHERE id = ?", (assignment["organization_id"],)).fetchone()
        evidence_timeline = [evidence_manifest_item(row) for row in evidence_rows_for(connection, assignment_id)]
        manifest = {
            "schema": "esense.document-package.v2",
            "package": {
                "id": package_id,
                "version": version,
                "title": title or f"Dokumentasjon - {assignment['title']}",
                "property_reference": property_reference,
                "summary": summary,
                "tests_and_results": tests_and_results,
                "deviations": deviations,
                "handover_notes": handover_notes,
                "safe_closure": safe_closure,
                "evidence_references": evidence_references,
                "owner_email": owner_email,
                "issued_at": timestamp,
            },
            "issuer": {
                "organization_id": assignment["organization_id"],
                "organization_name": organization["name"],
                "issued_by_user_id": user["id"],
                "issued_by_name": user["display_name"],
            },
            "assignment": serialize_assignment(assignment),
            "accepted_submission": {
                "id": submission["id"],
                "version": submission["version"],
                "snapshot": parse_json(submission["snapshot_json"], {}),
                "reviews": [
                    {
                        "decision": row["decision"],
                        "summary": row["summary"],
                        "findings": parse_json(row["findings_json"], []),
                        "reviewer_name": row["reviewer_name"],
                        "created_at": row["created_at"],
                    }
                    for row in reviews
                ],
            },
            "accepted_completion": {
                "id": completion_submission["id"],
                "version": completion_submission["version"],
                "snapshot": completion_snapshot,
                "reviews": [
                    {
                        "decision": row["decision"],
                        "summary": row["summary"],
                        "findings": parse_json(row["findings_json"], []),
                        "reviewer_name": row["reviewer_name"],
                        "created_at": row["created_at"],
                    }
                    for row in completion_reviews
                ],
            },
            "evidence_timeline": evidence_timeline,
        }
        salt = secrets.token_hex(32)
        commitment = document_commitment(manifest, salt)
        signature = document_signature(manifest, commitment)
        encrypted_manifest = encrypt_document_manifest(manifest, package_id)
        connection.execute(
            """
            INSERT INTO document_packages
                (id, assignment_id, organization_id, submission_id, version, title, property_reference,
                 summary, owner_email, status, manifest_json, commitment_salt, commitment,
                 receipt_signature, signing_method, midnight_status, created_by, issued_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', ?, ?, ?, ?, 'server_hmac_sha256',
                    'not_submitted', ?, ?, ?, ?)
            """,
            (
                package_id,
                assignment_id,
                assignment["organization_id"],
                submission["id"],
                version,
                "Beskyttet dokumentasjon",
                "Beskyttet anleggsreferanse",
                "Beskyttet dokumentasjonspakke",
                "Beskyttet mottaker",
                encrypted_manifest,
                salt,
                commitment,
                signature,
                user["id"],
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        anchor_queued = enqueue_midnight_anchor(connection, package_id, commitment, "register")
        owner_user = connection.execute("SELECT id FROM users WHERE lower(email) = ?", (owner_email,)).fetchone()
        connection.execute(
            """
            INSERT INTO document_access_grants
                (id, package_id, recipient_email, recipient_user_id, grant_type, purpose, expires_at,
                 status, granted_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'owner', ?, '', 'active', ?, ?, ?)
            """,
            (new_id("grt"), package_id, owner_email, owner_user["id"] if owner_user else None, purpose, user["id"], timestamp, timestamp),
        )
        audit(
            connection,
            "document_package.issued",
            user["id"],
            assignment["organization_id"],
            assignment_id,
            {
                "package_id": package_id,
                "version": version,
                "commitment": commitment,
                "midnight_anchor_queued": anchor_queued,
            },
        )
        package = document_package_row(connection, package_id)
        result = serialize_document_package(connection, package, user)
    return jsonify({"ok": True, "document_package": result}), 201


@app.post("/api/document-packages/<package_id>/grants")
@login_required
def grant_document_access(package_id: str):
    user = current_user()
    payload = json_payload()
    recipient_email = normalize_email(payload.get("recipient_email", ""))
    grant_type = str(payload.get("grant_type", "contractor")).strip()
    purpose = str(payload.get("purpose", "")).strip()[:1000]
    expires_at = str(payload.get("expires_at", "")).strip()[:40]
    if "@" not in recipient_email or grant_type not in {"owner", "contractor", "authority"} or not purpose:
        abort(400, "Mottaker, tilgangstype og formål er påkrevd")
    if grant_type != "owner" and (not expires_at or timestamp_expired(expires_at)):
        abort(400, "Tidsbegrenset tilgang må ha en fremtidig utløpsdato")
    timestamp = now_iso()
    with db() as connection:
        package = document_package_row(connection, package_id)
        if not can_manage_document_package(connection, package, user):
            abort(403)
        if package["status"] == "revoked":
            abort(409, "En tilbakekalt dokumentasjonspakke kan ikke deles på nytt")
        recipient = connection.execute("SELECT id FROM users WHERE lower(email) = ?", (recipient_email,)).fetchone()
        connection.execute(
            """
            INSERT INTO document_access_grants
                (id, package_id, recipient_email, recipient_user_id, grant_type, purpose, expires_at,
                 status, granted_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
            ON CONFLICT(package_id, recipient_email, grant_type) DO UPDATE SET
                recipient_user_id = excluded.recipient_user_id,
                purpose = excluded.purpose,
                expires_at = excluded.expires_at,
                status = 'active',
                granted_by = excluded.granted_by,
                updated_at = excluded.updated_at
            """,
            (new_id("grt"), package_id, recipient_email, recipient["id"] if recipient else None, grant_type, purpose, expires_at, user["id"], timestamp, timestamp),
        )
        audit(
            connection,
            "document_access.granted",
            user["id"],
            package["organization_id"],
            package["assignment_id"],
            {"package_id": package_id, "recipient_email": recipient_email, "grant_type": grant_type, "expires_at": expires_at},
        )
        refreshed = document_package_row(connection, package_id)
        result = serialize_document_package(connection, refreshed, user)
    return jsonify({"ok": True, "document_package": result}), 201


@app.post("/api/document-packages/<package_id>/grants/<grant_id>/revoke")
@login_required
def revoke_document_access(package_id: str, grant_id: str):
    user = current_user()
    timestamp = now_iso()
    with db() as connection:
        package = document_package_row(connection, package_id)
        if not can_manage_document_package(connection, package, user):
            abort(403)
        grant = connection.execute(
            "SELECT * FROM document_access_grants WHERE id = ? AND package_id = ?",
            (grant_id, package_id),
        ).fetchone()
        if not grant:
            abort(404)
        connection.execute(
            "UPDATE document_access_grants SET status = 'revoked', updated_at = ? WHERE id = ?",
            (timestamp, grant_id),
        )
        audit(
            connection,
            "document_access.revoked",
            user["id"],
            package["organization_id"],
            package["assignment_id"],
            {"package_id": package_id, "grant_id": grant_id, "recipient_email": grant["recipient_email"]},
        )
        refreshed = document_package_row(connection, package_id)
        result = serialize_document_package(connection, refreshed, user)
    return jsonify({"ok": True, "document_package": result})


@app.post("/api/document-packages/<package_id>/revoke")
@login_required
def revoke_document_package(package_id: str):
    user = current_user()
    payload = json_payload()
    reason = str(payload.get("reason", "")).strip()[:1000]
    if not reason:
        abort(400, "Årsak til tilbakekalling er påkrevd")
    timestamp = now_iso()
    with db() as connection:
        package = document_package_row(connection, package_id)
        if not can_manage_document_package(connection, package, user):
            abort(403)
        connection.execute("UPDATE document_packages SET status = 'revoked', updated_at = ? WHERE id = ?", (timestamp, package_id))
        revocation_queued = False
        if package["midnight_status"] in {"confirmed", "revocation_failed"}:
            revocation_queued = enqueue_midnight_anchor(connection, package_id, package["commitment"], "revoke")
        elif package["midnight_status"] in {"queued", "failed"}:
            connection.execute(
                """
                UPDATE midnight_anchors
                SET status = 'cancelled', last_error = 'Package revoked before submission', updated_at = ?
                WHERE package_id = ? AND operation = 'register' AND status IN ('queued', 'failed')
                """,
                (timestamp, package_id),
            )
            connection.execute(
                "UPDATE document_packages SET midnight_status = 'not_submitted', updated_at = ? WHERE id = ?",
                (timestamp, package_id),
            )
        audit(
            connection,
            "document_package.revoked",
            user["id"],
            package["organization_id"],
            package["assignment_id"],
            {"package_id": package_id, "reason": reason, "midnight_revocation_queued": revocation_queued},
        )
    return jsonify({"ok": True, "status": "revoked"})


@app.get("/api/document-packages/<package_id>/verify")
@login_required
def verify_document_package(package_id: str):
    user = current_user()
    with db() as connection:
        package = document_package_row(connection, package_id)
        if not can_view_document_package(connection, package, user):
            abort(403)
        try:
            manifest = decrypt_document_manifest(package["manifest_json"], package["id"])
            commitment = document_commitment(manifest, package["commitment_salt"])
            signature = document_signature(manifest, package["commitment"])
            commitment_valid = hmac.compare_digest(commitment, package["commitment"])
            signature_valid = hmac.compare_digest(signature, package["receipt_signature"])
        except (InvalidTag, KeyError, ValueError):
            commitment_valid = False
            signature_valid = False
        midnight = midnight_anchor_summary(connection, package)
        return jsonify(
            {
                "package_id": package["id"],
                "status": package["status"],
                "issued_at": package["issued_at"],
                "commitment": package["commitment"],
                "integrity": {
                    "valid": commitment_valid and signature_valid,
                    "commitment_valid": commitment_valid,
                    "server_signature_valid": signature_valid,
                    "signing_method": package["signing_method"],
                },
                "midnight": midnight,
            }
        )


@app.post("/api/internal/midnight/anchors/claim")
def claim_midnight_anchor():
    if not MIDNIGHT_READY:
        abort(503, "Midnight anchoring is not configured")
    timestamp = now_iso()
    stale_before = (datetime.now(UTC) - timedelta(minutes=45)).isoformat()
    with db() as connection:
        connection.execute(
            """
            UPDATE midnight_anchors
            SET status = 'failed', last_error = 'Worker lease expired before completion',
                next_attempt_at = ?, locked_at = '', updated_at = ?
            WHERE status = 'proving' AND locked_at != '' AND locked_at < ?
            """,
            (timestamp, timestamp, stale_before),
        )
        anchor = connection.execute(
            """
            SELECT ma.*, p.status AS package_status, p.organization_id, p.assignment_id
            FROM midnight_anchors ma
            JOIN document_packages p ON p.id = ma.package_id
            WHERE ma.status IN ('queued', 'failed')
              AND (ma.next_attempt_at = '' OR ma.next_attempt_at <= ?)
            ORDER BY CASE ma.status WHEN 'queued' THEN 0 ELSE 1 END, ma.created_at
            LIMIT 1
            """,
            (timestamp,),
        ).fetchone()
        if not anchor:
            return jsonify({"job": None})
        if anchor["operation"] == "register" and anchor["package_status"] == "revoked":
            connection.execute(
                "UPDATE midnight_anchors SET status = 'cancelled', updated_at = ? WHERE id = ?",
                (timestamp, anchor["id"]),
            )
            connection.execute(
                "UPDATE document_packages SET midnight_status = 'not_submitted', updated_at = ? WHERE id = ?",
                (timestamp, anchor["package_id"]),
            )
            return jsonify({"job": None})
        connection.execute(
            """
            UPDATE midnight_anchors
            SET status = 'proving', attempts = attempts + 1, locked_at = ?, last_error = '', updated_at = ?
            WHERE id = ?
            """,
            (timestamp, timestamp, anchor["id"]),
        )
        package_status = "proving" if anchor["operation"] == "register" else "revocation_pending"
        connection.execute(
            "UPDATE document_packages SET midnight_status = ?, updated_at = ? WHERE id = ?",
            (package_status, timestamp, anchor["package_id"]),
        )
        return jsonify(
            {
                "job": {
                    "id": anchor["id"],
                    "commitment": anchor["commitment"],
                    "operation": anchor["operation"],
                    "network": anchor["network"],
                    "contract_address": anchor["contract_address"],
                }
            }
        )


@app.post("/api/internal/midnight/anchors/<anchor_id>/result")
def report_midnight_anchor(anchor_id: str):
    payload = json_payload()
    result_status = str(payload.get("status", "")).strip()
    if result_status not in {"confirmed", "failed"}:
        abort(400, "A terminal worker status is required")
    transaction_id = str(payload.get("transaction_id") or "").strip()[:200]
    block_hash = str(payload.get("block_hash") or "").strip()[:200]
    verification_method = str(payload.get("verification_method") or "finalized_transaction").strip()
    if verification_method not in {"finalized_transaction", "contract_state"}:
        abort(400, "Unsupported verification method")
    try:
        block_height = int(payload["block_height"]) if payload.get("block_height") is not None else None
    except (TypeError, ValueError):
        abort(400, "Invalid block height")
    timestamp = now_iso()
    with db() as connection:
        anchor = connection.execute(
            """
            SELECT ma.*, p.status AS package_status, p.organization_id, p.assignment_id
            FROM midnight_anchors ma
            JOIN document_packages p ON p.id = ma.package_id
            WHERE ma.id = ?
            """,
            (anchor_id,),
        ).fetchone()
        if not anchor:
            abort(404)
        if result_status == "confirmed":
            connection.execute(
                """
                UPDATE midnight_anchors
                SET status = 'confirmed', transaction_id = ?, block_hash = ?, block_height = ?,
                    verification_method = ?, submitted_at = CASE WHEN submitted_at = '' THEN ? ELSE submitted_at END,
                    confirmed_at = ?, next_attempt_at = '', locked_at = '', last_error = '', updated_at = ?
                WHERE id = ?
                """,
                (
                    transaction_id or None,
                    block_hash or None,
                    block_height,
                    verification_method,
                    timestamp,
                    timestamp,
                    timestamp,
                    anchor_id,
                ),
            )
            package_midnight_status = "confirmed" if anchor["operation"] == "register" else "revoked"
            connection.execute(
                "UPDATE document_packages SET midnight_status = ?, updated_at = ? WHERE id = ?",
                (package_midnight_status, timestamp, anchor["package_id"]),
            )
            if anchor["operation"] == "register" and anchor["package_status"] == "revoked":
                enqueue_midnight_anchor(connection, anchor["package_id"], anchor["commitment"], "revoke")
        else:
            attempts = max(1, int(anchor["attempts"]))
            delay_minutes = min(360, 2 ** min(attempts, 8))
            next_attempt = (datetime.now(UTC) + timedelta(minutes=delay_minutes)).isoformat()
            error_message = str(payload.get("error") or "Midnight worker operation failed").strip()[:500]
            connection.execute(
                """
                UPDATE midnight_anchors
                SET status = 'failed', last_error = ?, next_attempt_at = ?, locked_at = '', updated_at = ?
                WHERE id = ?
                """,
                (error_message, next_attempt, timestamp, anchor_id),
            )
            package_midnight_status = "failed" if anchor["operation"] == "register" else "revocation_failed"
            connection.execute(
                "UPDATE document_packages SET midnight_status = ?, updated_at = ? WHERE id = ?",
                (package_midnight_status, timestamp, anchor["package_id"]),
            )
        audit(
            connection,
            f"midnight_anchor.{result_status}",
            None,
            anchor["organization_id"],
            anchor["assignment_id"],
            {
                "anchor_id": anchor_id,
                "package_id": anchor["package_id"],
                "operation": anchor["operation"],
                "transaction_id": transaction_id or None,
                "verification_method": verification_method,
            },
        )
    return jsonify({"ok": True, "status": result_status})


@app.get("/api/policy")
@login_required
def policy_metadata():
    policy = load_policy()
    return jsonify({"id": policy["id"], "version": policy["version"], "status": policy["status"], "notice": policy["notice"], "source_count": len(policy["sources"])})


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
