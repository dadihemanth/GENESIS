from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel


class TestConnectionResult(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
