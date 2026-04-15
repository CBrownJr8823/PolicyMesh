from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(str, Enum):
    allow = "allow"
    redact = "redact"
    require_approval = "require_approval"
    block = "block"


class DataClassification(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    regulated = "regulated"
    secret = "secret"


class ActionType(str, Enum):
    read_record = "read_record"
    write_record = "write_record"
    export_data = "export_data"
    send_email = "send_email"
    query_database = "query_database"
    invoke_external_api = "invoke_external_api"
    delete_record = "delete_record"


class AgentActionRequest(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-]+$")
    agent_role: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9_\- ]+$")
    user_id: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9_\-]+$")
    user_role: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9_\- ]+$")
    action_type: ActionType
    resource: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-zA-Z0-9_\-./]+$")
    target_system: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-zA-Z0-9_\- ]+$")
    data_classification: DataClassification
    destination: Optional[str] = Field(default=None, max_length=120)
    contains_pii: bool = False
    contains_financial_ bool = False
    contains_credentials: bool = False
    prompt_text: str = Field(..., min_length=1, max_length=3000)
    requested_fields: List[str] = Field(default_factory=list, max_length=20)
    justification: str = Field(..., min_length=5, max_length=500)

    @field_validator("requested_fields")
    @classmethod
    def validate_fields(cls, value: List[str]) -> List[str]:
        cleaned = []
        for item in value:
            item = item.strip()
            if not item:
                continue
            if len(item) > 50:
                raise ValueError("Requested field name too long")
            cleaned.append(item)
        return cleaned

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Destination too short")
        return value


class PolicyReason(BaseModel):
    code: str
    message: str
    risk_level: RiskLevel


class AgentActionResponse(BaseModel):
    decision: Decision
    risk_score: int = Field(..., ge=0, le=100)
    reasons: List[PolicyReason]
    redacted_fields: List[str] = []
    approval_required: bool = False
    allowed: bool
