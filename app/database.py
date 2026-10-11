"""
SQLite persistence layer for Veyra AI Security Engine.

Stores structured prompt analysis telemetry, verdicts, categories, risk scores,
and deterministic rule triggers.

PRIVACY DIRECTIVE:
By default, untrusted prompts are NOT stored in the database to prevent accidental
retention of confidential data, secrets, or sensitive employee inputs.
Prompt storage is strictly opt-in via the STORE_RAW_PROMPTS=true environment flag.

DIGITALOCEAN PERSISTENCE NOTE:
Container filesystems on DigitalOcean App Platform are ephemeral. To ensure database
durability across deployments and container rebuilds, mount a Persistent Volume
at /app/data and configure DATABASE_PATH=/app/data/veyra.db, or point to a
managed PostgreSQL instance for scalable distributed clustering.
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas import (
    AttackCategory,
    Decision,
    PromptAnalysisResult,
)

DEFAULT_DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "veyra.db"))


def _should_store_raw_prompts() -> bool:
    """Check if raw prompt logging is explicitly opted into via environment variable."""
    return os.environ.get("STORE_RAW_PROMPTS", "false").strip().lower() in ("true", "1", "yes")


def get_db_path() -> str:
    """Return configured SQLite database file path."""
    return os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Open connection to SQLite database with foreign keys and Row factory enabled.
    Creates parent directories if necessary.
    """
    target_path = db_path or get_db_path()
    parent_dir = os.path.dirname(os.path.abspath(target_path))
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize SQLite schema and indexes for Veyra analysis logs.
    Safe to call multiple times (idempotent).
    """
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                decision TEXT NOT NULL,
                category TEXT NOT NULL,
                risk_score REAL NOT NULL,
                confidence REAL NOT NULL,
                explanation TEXT NOT NULL,
                analysis_status TEXT NOT NULL,
                inference_mode TEXT NOT NULL,
                pipeline_latency_ms REAL,
                prompt_length INTEGER NOT NULL DEFAULT 0,
                prompt_text TEXT,
                evidence_json TEXT,
                rule_findings_json TEXT,
                metadata_json TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(timestamp DESC);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_decision ON analyses(decision);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_category ON analyses(category);")
        conn.commit()


def save_analysis(
    result: PromptAnalysisResult,
    prompt: Optional[str] = None,
    analysis_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist an analysis record into SQLite.
    
    Args:
        result: The PromptAnalysisResult returned by the detector
        prompt: Raw prompt text (only stored if STORE_RAW_PROMPTS=true)
        analysis_id: Optional custom ID; if omitted, generates UUID v4
        db_path: Optional database override path
        
    Returns:
        Dict representation of the persisted record
    """
    init_db(db_path)
    record_id = analysis_id or f"vy-{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    prompt_len = len(prompt) if prompt else (result.metadata.get("prompt_length", 0) if result.metadata else 0)

    # Opt-in prompt privacy gate
    stored_prompt = prompt if (_should_store_raw_prompts() and prompt) else None

    # Serialize JSON arrays
    evidence_json = json.dumps(result.evidence)
    rule_findings_json = json.dumps([f.model_dump() for f in result.rule_findings])
    metadata_json = json.dumps(result.metadata)

    decision_str = result.decision.value if hasattr(result.decision, "value") else str(result.decision)
    category_str = result.category.value if hasattr(result.category, "value") else str(result.category)
    status_str = result.analysis_status.value if hasattr(result.analysis_status, "value") else str(result.analysis_status)
    inference_str = result.inference_mode.value if hasattr(result.inference_mode, "value") else str(result.inference_mode)

    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                id, timestamp, decision, category, risk_score, confidence,
                explanation, analysis_status, inference_mode, pipeline_latency_ms,
                prompt_length, prompt_text, evidence_json, rule_findings_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                record_id,
                now_iso,
                decision_str,
                category_str,
                float(result.risk_score),
                float(result.confidence),
                result.explanation,
                status_str,
                inference_str,
                result.pipeline_latency_ms,
                int(prompt_len),
                stored_prompt,
                evidence_json,
                rule_findings_json,
                metadata_json,
            ),
        )
        conn.commit()

    return {
        "id": record_id,
        "timestamp": now_iso,
        "decision": decision_str,
        "category": category_str,
        "risk_score": float(result.risk_score),
        "confidence": float(result.confidence),
        "explanation": result.explanation,
        "analysis_status": status_str,
        "inference_mode": inference_str,
        "pipeline_latency_ms": result.pipeline_latency_ms,
        "prompt_length": prompt_len,
        "prompt_stored": stored_prompt is not None,
        "evidence": result.evidence,
        "rule_findings": [f.model_dump() for f in result.rule_findings],
        "metadata": result.metadata,
    }


def get_analysis(analysis_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full analysis record by unique ID."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?;", (analysis_id,)).fetchone()
        if not row:
            return None
        return _row_to_dict(row)


def get_history(
    limit: int = 50,
    offset: int = 0,
    decision: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Retrieve paginated analysis history with optional filters.
    
    Returns:
        Tuple of (list_of_records, total_matching_count)
    """
    init_db(db_path)
    conditions: List[str] = []
    params: List[Any] = []

    if decision:
        conditions.append("decision = ?")
        params.append(decision.upper())

    if category:
        conditions.append("category = ?")
        params.append(category.lower())

    if search:
        conditions.append("(explanation LIKE ? OR id LIKE ?)")
        search_pattern = f"%{search}%"
        params.extend([search_pattern, search_pattern])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection(db_path) as conn:
        # Total count query
        count_query = f"SELECT COUNT(*) FROM analyses {where_clause};"
        total_count = conn.execute(count_query, params).fetchone()[0]

        # Paginated data query
        data_query = f"""
            SELECT * FROM analyses
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?;
        """
        data_params = list(params) + [max(1, limit), max(0, offset)]
        cursor = conn.execute(data_query, data_params)
        rows = cursor.fetchall()

        results = [_row_to_dict(row) for row in rows]
        return results, total_count


def get_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Calculate real database analytics:
    Total count, decision breakdown, category breakdown, average risk, and inference modes.
    """
    init_db(db_path)
    with get_connection(db_path) as conn:
        total_count = conn.execute("SELECT COUNT(*) FROM analyses;").fetchone()[0]

        # Decision breakdown
        decisions_cursor = conn.execute(
            "SELECT decision, COUNT(*) as count FROM analyses GROUP BY decision;"
        )
        decisions_map: Dict[str, int] = {d.value: 0 for d in Decision}
        for row in decisions_cursor.fetchall():
            decisions_map[row["decision"]] = row["count"]

        # Category distribution
        categories_cursor = conn.execute(
            "SELECT category, COUNT(*) as count FROM analyses GROUP BY category;"
        )
        categories_map: Dict[str, int] = {c.value: 0 for c in AttackCategory}
        for row in categories_cursor.fetchall():
            categories_map[row["category"]] = row["count"]

        # Average risk and average latency
        avg_row = conn.execute(
            "SELECT AVG(risk_score) as avg_risk, AVG(pipeline_latency_ms) as avg_latency FROM analyses;"
        ).fetchone()
        avg_risk = round(avg_row["avg_risk"] or 0.0, 3)
        avg_latency = round(avg_row["avg_latency"] or 0.0, 2)

        # Inference mode distribution
        inference_cursor = conn.execute(
            "SELECT inference_mode, COUNT(*) as count FROM analyses GROUP BY inference_mode;"
        )
        inference_modes: Dict[str, int] = {}
        for row in inference_cursor.fetchall():
            inference_modes[row["inference_mode"]] = row["count"]

        return {
            "total_analyses": total_count,
            "allowed_count": decisions_map.get(Decision.ALLOW.value, 0),
            "blocked_count": decisions_map.get(Decision.BLOCK.value, 0),
            "quarantined_count": decisions_map.get(Decision.QUARANTINE.value, 0),
            "categories": categories_map,
            "average_risk_score": avg_risk,
            "average_latency_ms": avg_latency,
            "inference_modes": inference_modes,
        }


def clear_database(db_path: Optional[str] = None) -> None:
    """Clear all analysis records (used in automated test setup/teardown)."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM analyses;")
        conn.commit()


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert an SQLite Row to standard JSON-serializable dictionary."""
    evidence = []
    if row["evidence_json"]:
        try:
            evidence = json.loads(row["evidence_json"])
        except Exception:
            evidence = []

    rule_findings = []
    if row["rule_findings_json"]:
        try:
            rule_findings = json.loads(row["rule_findings_json"])
        except Exception:
            rule_findings = []

    metadata = {}
    if row["metadata_json"]:
        try:
            metadata = json.loads(row["metadata_json"])
        except Exception:
            metadata = {}

    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "decision": row["decision"],
        "category": row["category"],
        "risk_score": row["risk_score"],
        "confidence": row["confidence"],
        "explanation": row["explanation"],
        "analysis_status": row["analysis_status"],
        "inference_mode": row["inference_mode"],
        "pipeline_latency_ms": row["pipeline_latency_ms"],
        "prompt_length": row["prompt_length"],
        "prompt_stored": row["prompt_text"] is not None,
        "prompt_text": row["prompt_text"],
        "evidence": evidence,
        "rule_findings": rule_findings,
        "metadata": metadata,
    }
