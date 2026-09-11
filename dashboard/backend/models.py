"""
Dashboard Backend Data Models (Pydantic)
========================================
Định nghĩa cấu trúc dữ liệu cho REST API requests.
"""

from pydantic import BaseModel


class InjectAttackRequest(BaseModel):
    attack_type: str  # Normal, Port_Scanning, Vulnerability_scanner, DDoS_TCP, DDoS_UDP, Uploading


class ThresholdRequest(BaseModel):
    threshold: float
