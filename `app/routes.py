from fastapi import APIRouter, Depends

from app.audit import write_audit_event
from app.models import AgentActionRequest, AgentActionResponse
from app.policy_engine import evaluate_action
from app.security import require_api_key

router = APIRouter()


@router.get("/health")
def healthcheck():
    return {"status": "ok", "service": "PolicyMesh"}


@router.post("/evaluate", response_model=AgentActionResponse, dependencies=[Depends(require_api_key)])
def evaluate(request: AgentActionRequest):
    response = evaluate_action(request)
    write_audit_event(
        "policy_evaluation",
        {
            "agent_id": request.agent_id,
            "user_id": request.user_id,
            "action_type": request.action_type.value,
            "target_system": request.target_system,
            "decision": response.decision.value,
            "risk_score": response.risk_score,
        },
    )
    return response
j
