from app.models import (
    AgentActionRequest,
    AgentActionResponse,
    Decision,
    PolicyReason,
    RiskLevel,
)

PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "bypass policy",
    "reveal hidden prompt",
    "return full ssn",
    "exfiltrate",
    "ignore all rules",
    "override system",
    "disable guardrails",
]

SENSITIVE_FIELDS = {
    "ssn",
    "social_security_number",
    "bank_account",
    "routing_number",
    "password",
    "api_key",
    "token",
}

HIGH_RISK_DESTINATIONS = {"gmail.com", "yahoo.com", "outlook.com", "dropbox.com", "pastebin.com"}
PRIVILEGED_ROLES = {"security_admin", "compliance_admin", "hr_admin", "payroll_admin"}


def _contains_prompt_injection(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in PROMPT_INJECTION_PATTERNS)


def _destination_risky(destination: str | None) -> bool:
    if not destination:
        return False
    lowered = destination.lower()
    return any(item in lowered for item in HIGH_RISK_DESTINATIONS)


def evaluate_action(request: AgentActionRequest) -> AgentActionResponse:
    reasons: list[PolicyReason] = []
    risk_score = 0
    redacted_fields: list[str] = []

    if _contains_prompt_injection(request.prompt_text):
        risk_score += 40
        reasons.append(
            PolicyReason(
                code="PROMPT_INJECTION_SIGNAL",
                message="Prompt text includes likely instruction override or exfiltration language.",
                risk_level=RiskLevel.critical,
            )
        )

    if request.contains_credentials:
        risk_score += 30
        reasons.append(
            PolicyReason(
                code="CREDENTIAL_EXPOSURE_RISK",
                message="Request includes credentials or secrets-related content.",
                risk_level=RiskLevel.critical,
            )
        )

    if request.contains_pii:
        risk_score += 15
        reasons.append(
            PolicyReason(
                code="PII_PRESENT",
                message="Request involves personally identifiable information.",
                risk_level=RiskLevel.high,
            )
        )

    if request.contains_financial_
        risk_score += 15
        reasons.append(
            PolicyReason(
                code="FINANCIAL_DATA_PRESENT",
                message="Request involves financial or payroll-related information.",
                risk_level=RiskLevel.high,
            )
        )

    requested_sensitive = [field for field in request.requested_fields if field.lower() in SENSITIVE_FIELDS]
    if requested_sensitive:
        risk_score += 20
        redacted_fields.extend(requested_sensitive)
        reasons.append(
            PolicyReason(
                code="SENSITIVE_FIELD_REQUEST",
                message="Requested fields include highly sensitive values that should be redacted or denied.",
                risk_level=RiskLevel.high,
            )
        )

    if request.action_type.value in {"export_data", "send_email", "invoke_external_api"} and _destination_risky(request.destination):
        risk_score += 25
        reasons.append(
            PolicyReason(
                code="RISKY_DESTINATION",
                message="The requested destination appears to be an untrusted or consumer destination.",
                risk_level=RiskLevel.critical,
            )
        )

    if request.data_classification.value in {"regulated", "secret"} and request.user_role not in PRIVILEGED_ROLES:
        risk_score += 25
        reasons.append(
            PolicyReason(
                code="INSUFFICIENT_PRIVILEGE",
                message="The user role is not allowed to access highly sensitive classified data directly.",
                risk_level=RiskLevel.critical,
            )
        )

    if request.action_type.value == "delete_record":
        risk_score += 15
        reasons.append(
            PolicyReason(
                code="DESTRUCTIVE_ACTION",
                message="Delete operations require stronger review due to irreversible impact.",
                risk_level=RiskLevel.high,
            )
        )

    if request.action_type.value == "export_data" and request.data_classification.value in {"confidential", "regulated", "secret"}:
        risk_score += 20
        reasons.append(
            PolicyReason(
                code="BULK_DATA_EGRESS",
                message="Exporting sensitive data creates elevated exfiltration risk.",
                risk_level=RiskLevel.critical,
            )
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        decision = Decision.block
        allowed = False
        approval_required = False
    elif risk_score >= 55:
        decision = Decision.require_approval
        allowed = False
        approval_required = True
    elif redacted_fields:
        decision = Decision.redact
        allowed = True
        approval_required = False
    else:
        decision = Decision.allow
        allowed = True
        approval_required = False

    if not reasons:
        reasons.append(
            PolicyReason(
                code="NO_MATERIAL_RISK",
                message="No material policy violations were detected for this action.",
                risk_level=RiskLevel.low,
            )
        )

    return AgentActionResponse(
        decision=decision,
        risk_score=risk_score,
        reasons=reasons,
        redacted_fields=sorted(set(redacted_fields)),
        approval_required=approval_required,
        allowed=allowed,
    )
