from fastapi import APIRouter, Depends, Request

from app.audit import write_audit_event
from app.auth import authenticate_user, create_access_token, get_current_user
from app.models import AgentActionRequest, AgentActionResponse, TokenRequest, TokenResponse, User
from app.policy_engine import evaluate_action
from app.rate_limit import check_rate_limit

router = APIRouter()


@router.get("/health")
def healthcheck():
    return {"status": "ok", "service": "PolicyMesh"}


@router.get("/ready")
def readiness():
    return {"status": "ready", "service": "PolicyMesh"}


@router.post("/auth/token", response_model=TokenResponse)
def login(form: TokenRequest, request: Request):
    check_rate_limit(request)
    user = authenticate_user(form)
    if not user:
        write_audit_event("failed_login", {"username": form.username})
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token({"sub": user.username, "role": user.role})
    write_audit_event("login_success", {"username": user.username, "role": user.role})
    return TokenResponse(access_token=token)


@router.post("/evaluate", response_model=AgentActionResponse)
def evaluate(request_body: AgentActionRequest, request: Request, current_user: User = Depends(get_current_user)):
    check_rate_limit(request)
    response = evaluate_action(request_body)
    write_audit_event(
        "policy_evaluation",
        {
            "authenticated_user": current_user.username,
            "user_role": current_user.role,
            "agent_id": request_body.agent_id,
            "requested_user_id": request_body.user_id,
            "action_type": request_body.action_type.value,
            "target_system": request_body.target_system,
            "decision": response.decision.value,
            "risk_score": response.risk_score,
        },
    )
    return response
