"""
OpenVAS / Greenbone Vulnerability Scanner API Router.
Provides endpoints for connector configuration, connection diagnostics,
and XML/CSV vulnerability report ingestion.
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin
from app.services.openvas_service import (
    get_openvas_status,
    update_openvas_config,
    test_openvas_connection,
    parse_openvas_xml,
    parse_openvas_csv,
    ingest_openvas_findings,
    generate_sample_openvas_xml
)

router = APIRouter(prefix="/openvas", tags=["OpenVAS Vulnerability Scanner"])


class OpenVASConfigPayload(BaseModel):
    """Schema for updating OpenVAS daemon connection configuration."""
    host: str = Field("127.0.0.1", description="OpenVAS / Greenbone daemon IP or hostname")
    port: int = Field(9390, description="GMP daemon listening port (default 9390)")
    username: str = Field("admin", description="GMP API username")
    use_tls: bool = Field(True, description="Enforce TLS communication")


@router.get("/status", response_model=Dict[str, Any])
async def get_status(
    _user: User = Depends(require_any_authenticated)
):
    """Returns current OpenVAS connector telemetry, configuration, and ingestion counters."""
    return get_openvas_status()


@router.post("/config", response_model=Dict[str, Any])
async def set_config(
    payload: OpenVASConfigPayload,
    _user: User = Depends(require_analyst_or_admin)
):
    """Updates OpenVAS / Greenbone connection parameters."""
    return update_openvas_config(
        host=payload.host,
        port=payload.port,
        username=payload.username,
        use_tls=payload.use_tls
    )


@router.post("/test-connection", response_model=Dict[str, Any])
async def test_connection(
    _user: User = Depends(require_analyst_or_admin)
):
    """Tests network reachability to the configured OpenVAS daemon port."""
    return test_openvas_connection()


@router.post("/import", response_model=Dict[str, Any])
async def import_report_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Ingests an OpenVAS XML or CSV report into Sentinel-X.
    Parses vulnerabilities, links them to assets, and updates risk scores.
    """
    filename = file.filename or ""
    content_bytes = await file.read()
    try:
        content_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must be valid UTF-8 text (XML or CSV)."
        ) from exc

    try:
        if filename.lower().endswith(".xml") or content_text.strip().startswith("<?xml") or "<report" in content_text:
            findings = parse_openvas_xml(content_text)
        elif filename.lower().endswith(".csv") or "," in content_text.splitlines()[0]:
            findings = parse_openvas_csv(content_text)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported format. Please upload an OpenVAS XML (*.xml) or CSV (*.csv) report."
            )
    except Exception as exc: # pylint: disable=broad-exception-caught
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse OpenVAS report: {str(exc)}"
        ) from exc

    return await ingest_openvas_findings(
        db=db,
        findings=findings,
        actor_email=current_user.email
    )


@router.post("/import-sample", response_model=Dict[str, Any])
async def import_sample_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Ingests a realistic OpenVAS XML report covering Router, CCTV Camera,
    and Network Server vulnerabilities for Phase 2 demonstration.
    """
    sample_xml = generate_sample_openvas_xml()
    findings = parse_openvas_xml(sample_xml)
    return await ingest_openvas_findings(
        db=db,
        findings=findings,
        actor_email=current_user.email
    )
