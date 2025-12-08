"""
Data models for log sources in the Agentless SIEM
"""
from typing import Literal, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class LogSource(BaseModel):
    """Schema for an agentless log source"""
    source_id: str = Field(..., description="Unique identifier for the source")
    display_name: str = Field(..., description="Human-readable name")
    hostname: str = Field(..., description="Source hostname")
    ip_address: str = Field(..., description="Source IP address")
    device_type: Literal["endpoint", "server", "network", "cloud"] = Field(
        ..., description="Type of device"
    )
    os_name: Literal["Windows", "Linux", "Cisco", "Other"] = Field(
        ..., description="Operating system or platform"
    )
    source_type: Literal["windows", "linux", "network", "cloud"] = Field(
        ..., description="Source category"
    )
    protocol: Literal["syslog_udp", "syslog_tcp", "wef", "snmp", "http"] = Field(
        ..., description="Collection protocol"
    )
    status: Literal["online", "delayed", "offline"] = Field(
        default="offline", description="Connection status"
    )
    last_seen: datetime = Field(
        default_factory=datetime.now, description="Last event received"
    )
    events_per_minute: int = Field(default=0, description="Current event rate")
    total_events: int = Field(default=0, description="Total events collected")
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk assessment score")

    class Config:
        json_schema_extra = {
            "example": {
                "source_id": "src_001",
                "display_name": "DC-Server-01",
                "hostname": "dc01.corp.local",
                "ip_address": "10.0.1.10",
                "device_type": "server",
                "os_name": "Windows",
                "source_type": "windows",
                "protocol": "wef",
                "status": "online",
                "last_seen": "2025-12-05T10:30:00Z",
                "events_per_minute": 45,
                "total_events": 12500,
                "risk_score": 15
            }
        }


def calculate_source_status(last_seen: datetime) -> Literal["online", "delayed", "offline"]:
    """
    Calculate source status based on last seen timestamp
    
    Rules:
    - online: last_seen < 5 seconds ago
    - delayed: 5-30 seconds ago
    - offline: > 30 seconds ago
    """
    delta = (datetime.now() - last_seen).total_seconds()
    
    if delta < 5:
        return "online"
    elif delta < 30:
        return "delayed"
    else:
        return "offline"
