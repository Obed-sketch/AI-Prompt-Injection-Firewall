"""
AI Prompt-Injection Firewall: a FastAPI proxy that scans untrusted chat
messages before forwarding them to a configured OpenAI-compatible LLM.
"""
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

UPSTREAM_URL = os.getenv("LLM_UPSTREAM_URL", "").rstrip("/")
UPSTREAM_API_KEY = os.getenv("LLM_UPSTREAM_API_KEY", "")
FIREWALL_API_KEY = os.getenv("FIREWALL_API_KEY", "")
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "60"))
MAX_BODY = int(os.getenv("MAX_BODY_BYTES", "1000000"))
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "5"))

app = FastAPI(title="AI Prompt-Injection Firewall", version="1.0.0")

# Transparent heuristic rules. These are indicators, not proof of an attack.
INJECTION_RULES = [
    (r"\b(ignore|disregard|forget|override)\b.{0,60}\b(previous|above|prior|all)\b.{0,30}\b(instructions?|rules?|prompts?)\b", 5, "instruction_override"),
    (r"\b(reveal|show|print|repeat|disclose|leak)\b.{0,50}\b(system prompt|developer message|hidden instructions?)\b", 5, "system_prompt_extraction"),
    (r"\b(act as|pretend to be|you are now)\b.{0,50}\b(unrestricted|unfiltered|developer mode|jailbreak)\b", 4, "role_override"),
    (r"\b(bypass|disable|circumvent|ignore)\b.{0,40}\b(safety|guardrails?|content filters?|policy)\b", 4, "safety_bypass"),
    (r"\b(exfiltrat(e|ion)|send|upload|forward|transmit)\b.{0,60}\b(secret|credentials?|passwords?|api keys?|private data)\b", 5, "data_exfiltration"),
    (r"\b(do not|don't|never)\b.{0,40}\b(tell|inform|alert|notify)\b.{0,30}\b(user|administrator|security)\b", 2, "concealment_instruction"),
]
SECRET_PATTERNS = [
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key_material"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "github_token_like"),
    (r"\bsk-[A-Za-z0-9_-]{20,}\b", "api_key_like"),
    (r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", "bearer_token"),
    (r"(?i)\b(password|passwd|secret|api[_ -]?key)\s*[:=]\s*['\"]?[^ \r\n'\"]{6,}", "credential_assignment"),
]
UNTRUSTED_ROLES = {"user", "tool", "function"}


class Finding(BaseModel):
    category: str
    severity: str
    score: int
    explanation: str


class ScanResult(BaseModel):
    allowed: bool
    score: int
    threshold: int
    findings: list[Finding] = Field(default_factory=list)
    message: str


def inspect_text(text: str) -> tuple[int, list[Finding]]:
    """Return a heuristic risk score and human-readable rule matches."""
    score = 0
    findings = []
    for pattern, weight, category in INJECTION_RULES:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            score += weight
            findings.append(Finding(
                category=category,
                severity="high" if weight >= 4 else "medium",
                score=weight,
                explanation=f"Matched a rule associated with {category.replace('_', ' ')}.",
            ))
    for pattern, category in SECRET_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            score += 5
            findings.append(Finding(
                category=category,
                severity="high",
                score=5,
                explanation="Content resembles a credential or private key. Avoid sending secrets to an LLM.",
            ))
    return score, findings


def scan_payload(payload: dict[str, Any]) -> ScanResult:
    """Inspect user/tool/function messages; system/developer are trusted by design."""
    messages = payload.get("messages")
    if not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="Request must contain a messages array.")
    total = 0
    findings = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        if str(message.get("role", "")).lower() not in UNTRUSTED_ROLES:
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "\n".join(
                str(part.get("text", "")) for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        else:
            text = ""
        score, matches = inspect_text(text)
        total += score
        findings.extend(matches)
    allowed = total < BLOCK_THRESHOLD
    return ScanResult(
        allowed=allowed, score=total, threshold=BLOCK_THRESHOLD,
        findings=findings,
        message="Request passed configured checks." if allowed else "Request blocked by the prompt-injection firewall.",
    )


def check_key(key: str | None) -> None:
    if FIREWALL_API_KEY and key != FIREWALL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid firewall API key.")


def check_upstream() -> None:
    parsed = urlparse(UPSTREAM_URL)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=503, detail="Configure a valid LLM_UPSTREAM_URL.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=503, detail="Do not put credentials in the upstream URL.")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ai-prompt-injection-firewall"}


@app.post("/scan", response_model=ScanResult)
async def scan_only(request: Request, x_firewall_key: str | None = Header(default=None)):
    """Scan only; useful for testing policies without calling a model."""
    check_key(x_firewall_key)
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Request body is too large.")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")
    return scan_payload(payload)


@app.post("/v1/chat/completions")
async def protected_chat(request: Request, x_firewall_key: str | None = Header(default=None)):
    """Block suspicious input; otherwise forward the original payload upstream."""
    check_key(x_firewall_key)
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail="Request body is too large.")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object.")

    result = scan_payload(payload)
    if not result.allowed:
        return JSONResponse(status_code=403, content={
            "error": {
                "type": "prompt_injection_blocked",
                "message": result.message,
                "score": result.score,
                "threshold": result.threshold,
                "findings": [item.model_dump() for item in result.findings],
            }
        })

    check_upstream()
    headers = {"Content-Type": "application/json"}
    if UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {UPSTREAM_API_KEY}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            upstream = await client.post(UPSTREAM_URL, json=payload, headers=headers)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="The upstream LLM timed out.")
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Could not reach the upstream LLM.")

    media_type = upstream.headers.get("content-type", "application/json").split(";")[0]
    return Response(content=upstream.content, status_code=upstream.status_code, media_type=media_type)
