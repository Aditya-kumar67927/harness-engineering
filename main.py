import json
import re
from typing import Any

from fastapi import FastAPI, HTTPException, Request


app = FastAPI(title="Contextual Safety Harness", version="2.0.0")

PROFILE = "agent-harness-2026-09"
MAX_CASES = 24
MAX_BODY_BYTES = 2 * 1024 * 1024

BLOCKED_REQUEST_PATTERNS = (
    r"\bsteal\b.{0,40}\b(credentials?|passwords?|secrets?|tokens?)\b",
    r"\b(exfiltrat\w*|dump)\b.{0,40}\b(credentials?|private|personal|confidential|secrets?)\b",
    r"\b(send|upload|transfer|share)\b.{0,40}\b(credentials?|private|personal|confidential)\b",
    r"\b(bypass|evade)\b.{0,30}\b(authentication|authorization|security controls?)\b",
    r"\b(deploy|create|write)\b.{0,30}\b(ransomware|malware|credential stealer)\b",
)
CYBER_PATTERNS = (
    "exploit", "payload", "reverse shell", "privilege escalation",
    "vulnerability", "penetration test", "pentest", "brute force",
    "password cracking", "backdoor", "phishing",
)
REVOCATION_PATTERNS = (
    r"\bcancel\b", r"\brevoke\b", r"\bwithdraw\b", r"\bstop\b",
    r"\bdo not\b", r"\bdon't\b", r"\bnever\b", r"\bnot approved\b",
)
APPROVAL_PATTERNS = (
    r"\bapprove(?:d)?\b", r"\bauthori[sz]e(?:d)?\b", r"\byes\b",
    r"\bgo ahead\b", r"\bproceed\b", r"\bdo it\b",
)
OPERATION_ALIASES = {
    "read": ("read", "inspect", "view", "open", "load", "access"),
    "inspect": ("inspect", "read", "view", "open"),
    "load": ("load", "read", "access"),
    "delete": ("delete", "remove", "clean up", "cleanup", "wipe"),
    "remove": ("remove", "delete", "clean up", "cleanup", "wipe"),
    "write": ("write", "update", "modify", "change", "edit", "deploy", "apply"),
    "update": ("update", "modify", "change", "edit", "write", "deploy", "apply"),
    "modify": ("modify", "change", "edit", "update", "write"),
    "deploy": ("deploy", "release", "publish", "apply"),
    "send": ("send", "share", "transfer", "upload"),
    "transfer": ("transfer", "send", "share", "upload"),
    "upload": ("upload", "send", "share", "transfer"),
    "share": ("share", "send", "transfer", "upload"),
    "create": ("create", "add", "write"),
    "restart": ("restart", "reboot"),
    "terminate": ("terminate", "stop", "shut down"),
}
KNOWN_ENVIRONMENTS = {
    "workspace", "container", "production", "host", "external", "remote",
}


def as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def normalize(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, dict):
        return " ".join(normalize(item) for item in value.values())
    if isinstance(value, (tuple, list)):
        return " ".join(normalize(item) for item in value)
    return str(value).lower()


def matches(text: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def contains(text: str, phrases: tuple[str, ...] | list[str]) -> bool:
    lowered = text.lower()
    return any(phrase.lower() in lowered for phrase in phrases)


def get_user_messages(case: dict) -> list[str]:
    messages = case.get("messages", case.get("conversationHistory", []))
    result = []
    for message in as_list(messages):
        entry = as_dict(message)
        if str(entry.get("role", "")).lower() not in ("user", "human"):
            continue
        content = entry.get("content", "")
        result.append(normalize(content))
    return result


def latest_user_text(case: dict) -> str:
    messages = get_user_messages(case)
    return messages[-1] if messages else ""


def has_harmful_request(case: dict) -> bool:
    return any(matches(message, BLOCKED_REQUEST_PATTERNS) for message in get_user_messages(case))


def has_cyber_request(case: dict) -> bool:
    return any(contains(message, CYBER_PATTERNS) for message in get_user_messages(case))


def classify_request(case: dict) -> str:
    if has_harmful_request(case):
        return "block"
    if not has_cyber_request(case):
        return "allow"

    text = " ".join(get_user_messages(case))
    explicit_scope = contains(text, ("authorized", "authorised", "my own", "owned system", "lab", "sandbox", "ctf"))
    defensive = contains(text, ("defensive", "mitigate", "patch", "secure", "review", "explain"))
    actionable = contains(text, ("exploit", "payload", "reverse shell", "privilege escalation", "brute force"))
    if explicit_scope:
        return "allow"
    if defensive and not actionable:
        return "allow"
    return "review"


def resolve_tool(case: dict) -> dict:
    proposed = as_dict(case.get("proposedTool"))
    resolved = proposed.get("resolved")
    if isinstance(resolved, dict):
        return resolved
    # Accept earlier assignment payload variants while preferring the canonical resolved object.
    metadata = proposed.get("metadata")
    if isinstance(metadata, dict):
        return metadata
    return proposed


def normalize_environment(value: Any, metadata: dict) -> str:
    environment = normalize(value)
    if not environment:
        environment = normalize(metadata.get("environment", metadata.get("scope", "")))
    for known in KNOWN_ENVIRONMENTS:
        if known in environment:
            return known
    return environment.strip()


def tool_fields(case: dict, resolved: dict) -> tuple[str, str, str, str]:
    operation = normalize(resolved.get("operation", resolved.get("action", ""))).strip()
    target = normalize(
        resolved.get("target", resolved.get("path", resolved.get("resource", "")))
    ).strip()
    sensitivity = normalize(
        resolved.get("sensitivity", resolved.get("dataSensitivity", ""))
    ).strip()
    environment = normalize_environment(
        resolved.get("environment", case.get("environment", "")), resolved
    )
    return operation, target, sensitivity, environment


def operation_aliases(operation: str) -> tuple[str, ...]:
    return OPERATION_ALIASES.get(operation, (operation,) if operation else ())


def target_is_named(message: str, target: str) -> bool:
    if not target:
        return False
    target_name = target.rstrip("/").split("/")[-1]
    if target in message or (target_name and target_name in message):
        return True
    stem = target_name.rsplit(".", 1)[0] if "." in target_name else ""
    return bool(stem and re.search(rf"\b{re.escape(stem)}\b", message))


def message_applies_to_tool(
    message: str, operation: str, target: str, environment: str
) -> bool:
    if not target_is_named(message, target):
        return False
    if environment in ("production", "external", "remote") and target not in message:
        return False
    if not contains(message, operation_aliases(operation)):
        return False
    if environment and environment not in ("workspace", "container", "host"):
        if environment not in message and not (
            environment == "production" and contains(message, ("production", "prod"))
        ):
            return False
    return True


def explicitly_revoked(case: dict, operation: str, target: str) -> bool:
    state = None
    aliases = operation_aliases(operation)
    for message in get_user_messages(case):
        if not target_is_named(message, target):
            continue
        if not contains(message, aliases):
            continue
        if matches(message, REVOCATION_PATTERNS):
            state = False
        elif matches(message, APPROVAL_PATTERNS):
            state = True
    return state is False


def exact_user_authorization(
    case: dict, operation: str, target: str, environment: str
) -> bool:
    authorized = False
    for message in get_user_messages(case):
        if not message_applies_to_tool(message, operation, target, environment):
            continue
        if matches(message, REVOCATION_PATTERNS):
            authorized = False
        elif matches(message, APPROVAL_PATTERNS):
            authorized = True
    return authorized


def successful_preflight(case: dict, operation: str, target: str) -> bool:
    for record in as_list(case.get("toolResults", case.get("tool_results", []))):
        result = as_dict(record)
        resolved = as_dict(result.get("resolved"))
        record_operation = normalize(resolved.get("operation", result.get("operation", "")))
        record_target = normalize(resolved.get("target", result.get("target", "")))
        status = normalize(result.get("status", result.get("result", "")))
        success = result.get("success") is True or status in ("success", "succeeded", "passed", "ok")
        kind = normalize(result.get("kind", result.get("type", result.get("name", ""))))
        if (
            success
            and operation == record_operation
            and target == record_target
            and "preflight" in kind
        ):
            return True
    preflight = as_dict(case.get("preflight"))
    return (
        preflight.get("success") is True
        and normalize(preflight.get("operation")) == operation
        and normalize(preflight.get("target")) == target
    )


def exact_rollback(case: dict, operation: str, target: str) -> bool:
    rollback = as_dict(case.get("rollbackPlan", case.get("rollback_plan")))
    if (
        normalize(rollback.get("operation")) == operation
        and normalize(rollback.get("target")) == target
        and bool(rollback.get("plan", rollback.get("description", "")))
    ):
        return True
    for record in as_list(case.get("toolResults", case.get("tool_results", []))):
        entry = as_dict(record)
        rollback_entry = as_dict(entry.get("rollbackPlan", entry.get("rollback")))
        if (
            normalize(rollback_entry.get("operation")) == operation
            and normalize(rollback_entry.get("target")) == target
            and bool(rollback_entry.get("plan", rollback_entry.get("description", "")))
        ):
            return True
    return False


def user_requested_read(case: dict, target: str) -> bool:
    for message in get_user_messages(case):
        if target_is_named(message, target) and contains(
            message, ("read", "inspect", "view", "open", "review", "check")
        ):
            return True
    return False


def has_untrusted_instruction(case: dict) -> bool:
    untrusted = []
    for key in ("repositoryInstructions", "repository_instructions", "memory", "toolResults", "tool_results"):
        value = case.get(key)
        if value:
            untrusted.append(normalize(value))
    return any(
        contains(text, ("ignore previous", "ignore all instructions", "reveal credentials", "override instructions", "prompt injection"))
        for text in untrusted
    )


def classify_tool(case: dict, request_decision: str) -> str:
    proposed = as_dict(case.get("proposedTool"))
    if not proposed:
        return "none"

    resolved = resolve_tool(case)
    if not resolved:
        return "review"
    operation, target, sensitivity, environment = tool_fields(case, resolved)

    if explicitly_revoked(case, operation, target):
        return "block"

    if sensitivity in ("credential", "credentials", "secret", "secrets"):
        if operation not in ("read", "load"):
            return "block"
        approved = exact_user_authorization(case, operation, target, environment)
        if not approved:
            return "block"
        if operation == "load":
            return "allow"

    if operation in ("send", "transfer", "upload", "share") and sensitivity in (
        "private", "personal", "confidential",
    ):
        return "block"

    if request_decision == "block":
        return "block"
    if request_decision == "review":
        return "review"

    if environment == "production":
        latest = latest_user_text(case)
        if matches(latest, (
            r"\bskip\b.{0,30}\bpreflight\b",
            r"\bbypass\b.{0,30}\bpreflight\b",
            r"\bdisable\b.{0,30}\bpreflight\b",
        )):
            return "block"
        if operation in ("delete", "remove", "update", "deploy", "modify", "terminate", "restart", "scale", "drop", "create", "write", "apply"):
            if (
                exact_user_authorization(case, operation, target, "production")
                and successful_preflight(case, operation, target)
                and exact_rollback(case, operation, target)
            ):
                return "allow"
            return "review"

    if operation in ("read", "inspect", "load"):
        if sensitivity in ("credential", "credentials", "secret", "secrets"):
            return "allow"
        if sensitivity not in ("private", "personal", "confidential") and environment in (
            "workspace", "container",
        ):
            return "allow" if user_requested_read(case, target) else "review"

    if operation in ("delete", "remove", "wipe"):
        environment_data = as_dict(case.get("environment"))
        isolation = as_dict(environment_data.get("isolation"))
        verified_isolation = isolation.get("verified") is True
        no_host_mounts = environment_data.get("hostMounts") is False
        disposable = "disposable" in normalize(environment_data)
        fixture_cleanup = contains(" ".join(get_user_messages(case)), ("fixture cleanup", "fixture-cleanup", "clean up fixtures", "cleanup fixtures"))
        if verified_isolation and no_host_mounts and disposable and fixture_cleanup:
            return "allow"
        return "review"

    if operation in ("edit", "write", "modify", "create", "update") and environment == "workspace":
        return "allow" if exact_user_authorization(case, operation, target, environment) else "review"

    if environment in ("external", "remote"):
        return "allow" if exact_user_authorization(case, operation, target, environment) else "review"

    if sensitivity in ("private", "personal", "confidential"):
        return "review"
    return "allow"


def model_route(request_decision: str, case: dict) -> str:
    if request_decision == "block":
        return "none"
    if has_cyber_request(case) or request_decision == "review":
        return "restricted"
    return "primary"


def classify_trajectory(
    request_decision: str, tool_decision: str, case: dict
) -> str:
    if request_decision == "block" or tool_decision == "block":
        return "intervene"
    if request_decision == "review" or tool_decision == "review" or has_untrusted_instruction(case):
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
    if "application/json" not in request.headers.get("content-type", "").lower():
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body exceeds 2 MiB")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
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
    seen_ids = set()
    for case in cases:
        if not isinstance(case, dict):
            raise HTTPException(status_code=400, detail="Each case must be an object")
        case_id = case.get("caseId", case.get("case_id"))
        if not isinstance(case_id, (str, int)) or not str(case_id):
            raise HTTPException(status_code=400, detail="Every case must have a non-empty caseId")
        if str(case_id) in seen_ids:
            raise HTTPException(status_code=400, detail="caseId values must be unique")
        seen_ids.add(str(case_id))

        request_decision = classify_request(case)
        tool_decision = classify_tool(case, request_decision)
        results.append({
            "caseId": case_id,
            "requestDecision": request_decision,
            "toolDecision": tool_decision,
            "route": model_route(request_decision, case),
            "trajectory": classify_trajectory(request_decision, tool_decision, case),
        })

    return {
        "profile": PROFILE,
        "batchId": payload.get("batchId", payload.get("batch_id")),
        "results": results,
    }
