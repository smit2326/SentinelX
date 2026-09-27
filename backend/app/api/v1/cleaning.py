"""
Phase 3 Data Cleaning & Validation API Router.
Provides endpoints for executing the Data Cleaning Pipeline,
inspecting data hygiene metrics, and testing normalization rules.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.user import User
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin
from app.services.audit_service import log_audit_event
from app.services.data_cleaning_pipeline import DataCleaningPipeline
from app.services.data_quality_layer import DataQualityLayer

router = APIRouter(prefix="/cleaning", tags=["Phase 3 — Data Cleaning & Hygiene Pipeline"])


class IPValidationPayload(BaseModel):
    """Schema for IP address validation."""
    ip: str = Field(..., description="IPv4 or IPv6 address to test")


class PortValidationPayload(BaseModel):
    """Schema for TCP/UDP port validation."""
    port: int = Field(..., description="Port number to evaluate")
    protocol: str = Field("tcp", description="Protocol: tcp or udp")


class OSNormalizationPayload(BaseModel):
    """Schema for operating system string normalization."""
    raw_os: str = Field(..., description="Raw OS string from banner, WMI, or scanner")
    version: Optional[str] = Field(None, description="Optional raw version string")
    build: Optional[str] = Field(None, description="Optional raw build number")


class SoftwareNormalizationPayload(BaseModel):
    """Schema for software banner version normalization."""
    banner: str = Field(..., description="Raw software banner e.g. OpenSSH_8.9p1")


@router.get("/status", response_model=Dict[str, Any])
async def get_cleaning_status(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns data hygiene and quality metrics across the Sentinel-X database.
    Evaluates null values, validation compliance, and total entities.
    """
    asset_count_res = await db.execute(select(func.count(Asset.id)))
    asset_count = asset_count_res.scalar() or 0

    vuln_count_res = await db.execute(select(func.count(Vulnerability.id)))
    vuln_count = vuln_count_res.scalar() or 0

    # Null value checks
    missing_hostname_res = await db.execute(select(func.count(Asset.id)).where(Asset.hostname.is_(None)))
    missing_hostnames = missing_hostname_res.scalar() or 0

    missing_mac_res = await db.execute(select(func.count(Asset.id)).where(Asset.mac_address.is_(None)))
    missing_macs = missing_mac_res.scalar() or 0

    return {
        "pipeline_version": "Phase 3 v1.0",
        "status": "READY",
        "total_assets": asset_count,
        "total_vulnerabilities": vuln_count,
        "hygiene_metrics": {
            "missing_hostnames": missing_hostnames,
            "missing_mac_addresses": missing_macs,
            "data_completeness_score": (
                round(((asset_count * 2 - (missing_hostnames + missing_macs)) / max(asset_count * 2, 1)) * 100, 1)
            )
        },
        "pipeline_steps": [
            "A. Remove duplicates (Composite key hash)",
            "B. Normalize operating systems (OS Family & Version Mapping)",
            "C. Normalize software versions (SemVer Regex Parser)",
            "D. Handle missing values (Domain-aware inference without synthetic hallucination)",
            "E. Validate IP addresses (IPv4 / IPv6 RFC standard parser)",
            "F. Validate ports (RFC [1, 65535] range and classification)",
            "G. Normalize timestamps (Unified UTC ISO-8601 standard)"
        ]
    }


@router.post("/run", response_model=Dict[str, Any])
async def execute_cleaning_pipeline(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Executes the full 7-step Data Cleaning Pipeline across the database.
    Deduplicates records, validates IPs/ports, normalizes OS/software, and standardizes timestamps.
    """
    report = await DataCleaningPipeline.clean_database_telemetry(db)

    await log_audit_event(
        db=db,
        action="DATA_CLEANING_PIPELINE_EXECUTED",
        resource="pipeline",
        actor_email=current_user.email,
        details=report
    )

    return {
        "success": True,
        "message": "Data cleaning and normalization pipeline completed successfully.",
        "cleaning_report": report
    }


@router.post("/validate-ip", response_model=Dict[str, Any])
async def validate_ip_endpoint(
    payload: IPValidationPayload,
    _user: User = Depends(require_any_authenticated)
):
    """Tests and validates an IP address according to RFC IPv4/IPv6 standards."""
    return DataCleaningPipeline.validate_ip(payload.ip)


@router.post("/validate-port", response_model=Dict[str, Any])
async def validate_port_endpoint(
    payload: PortValidationPayload,
    _user: User = Depends(require_any_authenticated)
):
    """Tests and validates a TCP/UDP port number and identifies its standard service."""
    return DataCleaningPipeline.validate_port(payload.port, payload.protocol)


@router.post("/normalize-os", response_model=Dict[str, Any])
async def normalize_os_endpoint(
    payload: OSNormalizationPayload,
    _user: User = Depends(require_any_authenticated)
):
    """Normalizes an unstructured operating system string into canonical family and version."""
    return DataCleaningPipeline.normalize_os(payload.raw_os, payload.version, payload.build)


@router.post("/normalize-software", response_model=Dict[str, Any])
async def normalize_software_endpoint(
    payload: SoftwareNormalizationPayload,
    _user: User = Depends(require_any_authenticated)
):
    """Normalizes raw software banner strings into structured product names and semantic versions."""
    return DataCleaningPipeline.normalize_software_version(payload.banner)


class QualityEvaluationPayload(BaseModel):
    """Schema for arbitrary telemetry record quality assessment."""
    ip_address: Optional[str] = Field(None, description="IP address of endpoint")
    hostname: Optional[str] = Field(None, description="Host identifier")
    os_name: Optional[str] = Field(None, description="Operating system name")
    os_build: Optional[str] = Field(None, description="OS build number")
    vendor: Optional[str] = Field(None, description="Hardware or vendor name")
    mac_address: Optional[str] = Field(None, description="Physical hardware MAC")
    source: str = Field("Windows Collector", description="Data collection source")


@router.get("/quality/summary", response_model=Dict[str, Any])
async def get_quality_summary_endpoint(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns platform-wide Data Quality Layer metrics:
    Tier distribution (Complete, Partial, Inferred, Degraded), confidence breakdown,
    source distribution, and completeness scores.
    """
    return await DataQualityLayer.get_quality_summary(db)


@router.post("/quality/audit", response_model=Dict[str, Any])
async def run_quality_audit_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """
    Executes a database-wide Data Quality Layer audit.
    Evaluates every asset, stamps quality passports, and retains records with transparent lineage.
    Philosophy: 'Don't just clean the data and throw bad records away.'
    """
    report = await DataQualityLayer.audit_database_assets(db)

    await log_audit_event(
        db=db,
        action="DATA_QUALITY_AUDIT_EXECUTED",
        resource="data_quality_layer",
        actor_email=current_user.email,
        details=report
    )

    return {
        "success": True,
        "message": "Data Quality Layer audit completed across asset inventory.",
        "audit_report": report
    }


@router.post("/quality/evaluate", response_model=Dict[str, Any])
async def evaluate_record_quality_endpoint(
    payload: QualityEvaluationPayload,
    _user: User = Depends(require_any_authenticated)
):
    """
    Interactive test endpoint for Phase 3 Data Quality Layer.
    Evaluates an arbitrary record dictionary and returns its Data Quality Passport.
    """
    record_dict = payload.model_dump()
    source = record_dict.pop("source", "Windows Collector")
    return DataQualityLayer.assess_record_quality(record_dict, source=source)
