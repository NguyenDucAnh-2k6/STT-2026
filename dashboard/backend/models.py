"""
Dashboard Backend Data Models (Pydantic)
========================================
Định nghĩa cấu trúc dữ liệu cho REST API requests.
"""

from typing import Optional
from pydantic import BaseModel, Field


class InjectAttackRequest(BaseModel):
    attack_type: str  # Normal, Port_Scanning, Vulnerability_scanner, DDoS_TCP, DDoS_UDP, Uploading


class AttackTriggerRequest(BaseModel):
    attack_type: str
    target_ip: Optional[str] = None


class AutoCycleRequest(BaseModel):
    enabled: bool = True


class ThresholdRequest(BaseModel):
    threshold: float


class ExperimentStartRequest(BaseModel):
    scenario: str
    duration_sec: int = Field(default=15, ge=1, le=60)
