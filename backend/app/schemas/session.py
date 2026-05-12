from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, field_validator

_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)
_BLOCKED_NAMES = {"localhost", "localhost.localdomain", "loopback"}


class SessionCreate(BaseModel):
    target_ip: str
    target_hostname: Optional[str] = None
    scan_profile: Optional[str] = "deep"
    agent_mode: Optional[str] = "multi_agent"
    config: Optional[Dict[str, Any]] = None

    @field_validator("target_ip")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        # Try as IP address first
        try:
            addr = ipaddress.ip_address(v)
            if addr.is_loopback:
                raise ValueError("Loopback addresses are not permitted as scan targets")
            if addr.is_link_local:
                raise ValueError("Link-local addresses are not permitted as scan targets")
            if addr.is_multicast:
                raise ValueError("Multicast addresses are not permitted as scan targets")
            if addr.is_unspecified:
                raise ValueError("Unspecified (0.0.0.0/::) addresses are not permitted")
            return v
        except ValueError as exc:
            if "not permitted" in str(exc):
                raise
        # Validate as hostname / FQDN
        if len(v) > 253:
            raise ValueError("Hostname exceeds maximum length of 253 characters")
        if v.lower() in _BLOCKED_NAMES:
            raise ValueError(f"'{v}' is not permitted as a scan target")
        if not _HOSTNAME_RE.match(v):
            raise ValueError("Invalid target: must be a valid IP address or hostname")
        return v


class SessionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_ip: str
    target_hostname: Optional[str]
    status: str
    phase: str
    iteration: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    summary: Optional[str]
    vulnerability_count: int
    critical_count: int
    high_count: int
    config: Dict[str, Any]
    scan_profile: str = "deep"
    agent_mode: str = "multi_agent"
    network_topology: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class SessionList(BaseModel):
    items: List[SessionRead]
    total: int
    page: int
    size: int


class AgentThoughtRead(BaseModel):
    id: str
    session_id: str
    thought: str
    phase: str
    iteration: int
    tool_calls: Optional[List[Any]] = None
    timestamp: datetime


class ToolOutputRead(BaseModel):
    id: str
    session_id: str
    tool_name: str
    params: Dict[str, Any]
    raw_output: Optional[str]
    parsed_output: Optional[Dict[str, Any]]
    duration_seconds: Optional[float]
    timestamp: datetime


class SessionErrorRead(BaseModel):
    id: str
    session_id: str
    phase: str
    error_type: str
    error_message: str
    traceback: Optional[str] = None
    iteration: Optional[int] = None
    tool: Optional[str] = None
    context: Dict[str, Any] = {}
    timestamp: datetime


class SessionErrorList(BaseModel):
    items: List[SessionErrorRead]
    total: int
