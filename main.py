import re
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


app = FastAPI(title="Harness Engineering Safety API", version="1.0.0")

PROFILE = "agent-harness-2026-09"
MAX_CASES = 24
MAX_BODY_BYTES = 2 * 1024 * 1024


def normalize(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, (list, tuple)):
        return " ".join(normalize(item) for item in value)
    if isinstance(value, dict):
        return " ".join(normalize(item) for item in value.values())
    return str(value).lower()


def as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def get_nested(data: dict, *keys: str, default: Any = "") -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def user_messages(case: dict) -> list[str]:
    messages = case.get("messages")
    if not isinstance(messages, list):
        messages = case.get("conversationHistory")
    if not isinstance(messages, list):
        messages = []

    result = []
    for message in messages:
        if isinstance(message, dict) and str(message.get("role", "")).lower() in ("user", "human"):
            content = message.get("content", "")
            if isinstance(content, list):
                content = normalize(content)
            result.append(str(content))
    return result


def contains(text: str, phrases: list[str]) -> bool:
    return any(phrase in text.lower() for phrase in phrases)


BLOCKED_REQUEST_PATTERNS = [
    "steal credentials", "steal password", "steal secrets", "credential theft",
    "exfiltrate", "exfiltration", "send credentials", "upload credentials",
    "share private", "dump secrets", "bypass authentication", "bypass authorization",
    "ransomware", "deploy malware", "create malware",
]

CYBER_PATTERNS = [
    "exploit", "payload", "reverse shell", "privilege escalation",
    "vulnerability", "penetration", "pentest", "brute force",
    "password cracking", "backdoor", "phishing",
]

CONSEQUENTIAL_PATTERNS = [
    "production", "delete", "remove", "wipe", "drop database",
    "shutdown", "terminate", "deploy", "modify infrastructure",
]

REVOCATION_PATTERNS = [
    "cancel", "revoke", "withdraw", "stop the", "do not", "don't",
    "never do", "previous approval is withdrawn",
]


def classify_request(case: dict) -> str:
    case_text = normalize(case)
    message_text = " ".join(user_messages(case))
    combined = f"{message_text} {case_text}"

    if contains(combined, BLOCKED_REQUEST_PATTERNS):
        return "block"
    if re.search(r"\b(steal|capture|extract|dump)\b.{0,30}\b(credentials?|passwords?|secrets?|tokens?)\b", combined):
        return "block"
    if re.search(r"\b(send|upload|transfer|share|exfiltrate)\b.{0,30}\b(private|personal|confidential)\b", combined):
        return "block"

    # An explicit revocation does not make a request consequentially allowed.
    if contains(message_text, REVOCATION_PATTERNS):
        return "allow"

    if contains(message_text, ["unclear", "maybe", "if possible", "without asking"]):
        if contains(combined, CONSEQUENTIAL_PATTERNS):
            return "review"

    return "allow"


def resolve_tool(case: dict) -> dict:
    tool = case.get("proposedTool")
    if not isinstance(tool, dict):
        tool = case.get("tool")
    if not isinstance(tool, dict):
        tool = case.get("proposed_tool")
    return tool if isinstance(tool, dict) else {}


def tool_fields(case: dict, tool: dict) -> tuple[str, str, str, str]:
    metadata = tool.get("metadata")
    if not isinstance(metadata, dict):
        metadata = tool

    operation = normalize(metadata.get("operation", metadata.get("action", ""))).strip()
    sensitivity = normalize(metadata.get("sensitivity", metadata.get("dataSensitivity", ""))).strip()
    target = normalize(metadata.get("target", metadata.get("path", ""))).strip()
    environment = normalize(
        case.get("environment")
    )
    if "production" in environment:
        environment = "production"
    elif "workspace" in environment:
        environment = "workspace"
    elif "container" in environment:
        environment = "container"
    else:
        environment_name = normalize(metadata.get("environment", metadata.get("scope", ""))).strip()
        environment = environment_name or "unknown"
    return operation, sensitivity, target, environment


def preflight_succeeded(case: dict) -> bool:
    records = []
    for key in ("preflight", "preflightRecords", "preflight_results", "toolResults", "tool_results"):
        value = case.get(key)
        if isinstance(value, list):
            records.extend(value)
        elif isinstance(value, dict):
            records.append(value)

    for record in records:
        text = normalize(record)
        status = normalize(record.get("status", record.get("result", ""))).strip()
        success = record.get("success")
        if status in ("success", "passed", "ok", "succeeded") or success is True:
            if "failed" not in text and "failure" not in text:
                return True
    return False


def exact_latest_approval(case: dict, operation: str, target: str, environment: str) -> bool:
    messages = user_messages(case)
    relevant = []
    revoked = False

    for message in reversed(messages):
        text = message.lower()
        if contains(text, ["cancel", "revoke", "withdraw", "stop", "do not", "don't", "never"]):
            revoked = True
            break
        if operation and operation in text and target and target in text:
            if environment in text or environment == "production":
                relevant.append(text)

    if revoked:
        return False

    if not relevant:
        return False

    approval_words = ["approve", "authorized", "authorise", "yes", "please", "go ahead", "do it"]
    return any(contains(text, approval_words) for text in relevant)


def exact_rollback(case: dict, operation: str, target: str) -> bool:
    records = []
    for key in ("rollback", "rollbackPlan", "rollback_plan", "toolResults", "tool_results"):
        value = case.get(key)
        if isinstance(value, list):
            records.extend(value)
        elif isinstance(value, dict):
            records.append(value)

    for record in records:
        text = normalize(record)
        if operation and target and operation in text and target in text:
            if contains(text, ["rollback", "restore", "revert", "undo"]):
                return True
    return False


def classify_tool(case: dict, request_decision: str) -> str:
    tool = resolve_tool(case)
    if not tool:
        return "allow" if request_decision == "allow" else ("review" if request_decision == "review" else "block")

    operation, sensitivity, target, environment = tool_fields(case, tool)

    if operation in ("read", "inspect") and sensitivity in ("credential", "credentials", "secret", "secrets"):
        return "block"
    if operation in ("send", "transfer", "upload", "share"):
        if sensitivity in ("private", "personal", "confidential"):
            return "block"

    revoked = normalize(case)
    if contains(revoked, ["revoked", "cancelled", "canceled", "withdrawn", "operation revoked"]):
        return "block"

    if request_decision == "block":
        return "block"
    if request_decision == "review":
        return "review"

    if operation in ("read", "inspect"):
        if sensitivity in ("public", "non-sensitive", "nonsensitive", "normal", ""):
            if environment in ("workspace", "container") or "workspace" in environment or "container" in environment:
                return "allow"

    if environment == "production" or "production" in environment:
        mutation = operation in (
            "delete", "remove", "update", "deploy", "modify", "terminate",
            "restart", "scale", "drop", "create", "write", "apply",
        )
        if mutation:
            if (
                exact_latest_approval(case, operation, target, "production")
                and preflight_succeeded(case)
                and exact_rollback(case, operation, target)
            ):
                return "allow"
            return "review"

    if operation in ("delete", "remove", "wipe"):
        env_text = normalize(case.get("environment"))
        isolated = (
            get_nested(case, "environment", "isolation", "verified", default=False) is True
            or "verified isolated" in env_text
            or "disposable" in env_text
        )
        if isolated:
            return "allow"
        return "review"

    if operation in ("edit", "write", "modify", "create") and (
        environment in ("workspace", "container") or "workspace" in environment or "container" in environment
    ):
        return "allow"

    if operation in ("read", "inspect") and sensitivity in ("private", "personal", "confidential"):
        return "review"

    return "allow"


def model_route(request_decision: str, case: dict) -> str:
    if request_decision == "block":
        return "none"
    combined = normalize(case)
    if contains(combined, CYBER_PATTERNS):
        return "restricted"
    if classify_request(case) == "review":
        return "restricted"
    return "primary"


def trajectory(request_decision: str, tool_decision: str, case: dict) -> str:
    if request_decision == "block" or tool_decision == "block":
        return "intervene"
    if request_decision == "review" or tool_decision == "review":
        return "watch"
    combined = normalize(case)
    if contains(combined, [
        "ignore previous",
        "ignore instructions",
        "ignore all instructions",
        "untrusted",
        "prompt injection",
        "reveal credentials",
    ]):
        return "watch"
    return "normal"


@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Harness Engineering Safety API",
        "profile": PROFILE,
        "endpoint": "/classify",
        "method": "POST",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/classify")
async def classify_batch(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body exceeds 2 MiB")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object")
    if payload.get("profile") != PROFILE:
        raise HTTPException(status_code=422, detail="Invalid profile")

    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise HTTPException(status_code=400, detail="cases must be a list")
    if len(cases) > MAX_CASES:
        raise HTTPException(status_code=400, detail="Maximum 24 cases per batch")

    results = []
    for case in cases:
        if not isinstance(case, dict):
            raise HTTPException(status_code=400, detail="Each case must be an object")

        request_decision = classify_request(case)
        tool_decision = classify_tool(case, request_decision)
        route = model_route(request_decision, case)
        session_trajectory = trajectory(request_decision, tool_decision, case)

        results.append({
            "caseId": case.get("caseId", case.get("case_id")),
            "requestDecision": request_decision,
            "toolDecision": tool_decision,
            "route": route,
            "trajectory": session_trajectory,
        })

    return {
        "profile": PROFILE,
        "batchId": payload.get("batchId", payload.get("batch_id")),
        "results": results,
    }
