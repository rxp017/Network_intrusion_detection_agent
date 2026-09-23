"""Provider-agnostic, async LLM narrative layer with waterfall failover.

Supports Groq and Gemini with automatic fallback on rate limits (429),
zero-dependency .env auto-loading, in-memory caching, non-blocking async
rate limiting, and literal grounding.

CRITICAL CONCURRENCY PROPERTY:
Outbound LLM HTTP requests are fully asynchronous using httpx.AsyncClient
and asyncio.sleep. They NEVER block the FastAPI asyncio event loop or hold
worker threads. Replay streams (/ws/stream) and REST endpoints continue ticking
at full speed without any latency jitter or freezing while an explanation is generated.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("nida.narrator")

SYSTEM_PROMPT = (
    "You are writing a short plain-English caption for a security analyst dashboard. "
    "You will be given a machine learning model's already-computed verdict for one "
    "network flow: a predicted category, a confidence score, a risk score/tier, "
    "a review recommendation, and the top contributing features from a SHAP explanation. "
    "Restate these facts in two parts: (1) a 2-3 sentence summary a non-technical "
    "person can understand, referencing only the specific features given to you, "
    "and (2) one sentence of recommended next action consistent with the review_recommended "
    "flag. Do not invent a different verdict, confidence, or risk level than the one given. "
    "Do not mention any feature that was not provided to you. Do not use the words 'certainly' "
    "or 'definitely' — this is a probabilistic model output, not a proven fact."
)

DEFAULT_MODELS = {
    "groq": "llama-3.3-70b-versatile",
    "gemini": "gemini-2.5-flash",
}

FALLBACK_SUMMARY = "AI narrative unavailable."
FALLBACK_ACTION = "Follow standard security review protocol."

# In-memory cache: hash(features + predicted class + risk_score) -> dict
_NARRATIVE_CACHE: dict[str, dict[str, str]] = {}
_CACHE_LOCK = threading.Lock()

# Rate limiting: minimum 2 seconds between outbound LLM calls process-wide
_RATE_LIMIT_SECONDS = 2.0
_LAST_CALL_TIMESTAMP = 0.0
_SYNC_RATE_LOCK = threading.Lock()
_ASYNC_RATE_LOCK = asyncio.Lock()


class ProviderQuotaExceeded(Exception):
    """Raised when an LLM provider returns 429 Too Many Requests or quota exhaustion."""

    pass


class ProviderError(Exception):
    """Raised when an LLM provider request fails with a non-recoverable error."""

    pass


def _load_dotenv() -> None:
    """Load key-value pairs from .env in project root if present and not already in os.environ."""
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.is_file():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
        except Exception as exc:
            logger.debug("Failed loading .env: %s", exc)


# Auto-load on import
_load_dotenv()


def get_configured_keys() -> dict[str, str]:
    """Return dictionary of configured provider API keys."""
    _load_dotenv()
    legacy_key = os.getenv("LLM_API_KEY", "").strip()
    legacy_provider = os.getenv("LLM_PROVIDER", "").strip().lower()

    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    if not groq_key and legacy_provider == "groq":
        groq_key = legacy_key

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key and legacy_provider == "gemini":
        gemini_key = legacy_key

    return {
        "groq": groq_key,
        "gemini": gemini_key,
    }


def get_waterfall_providers() -> list[tuple[str, str, str]]:
    """Return ordered list of (provider, api_key, model) candidates for waterfall execution.

    Waterfall priority:
    1. If LLM_PROVIDER is 'none', returns empty list (guarantees 100% offline).
    2. If LLM_PROVIDER is 'groq': Groq is primary; Gemini is fallback if GEMINI_API_KEY is present.
    3. If LLM_PROVIDER is 'gemini': Gemini is primary; Groq is fallback if GROQ_API_KEY is present.
    4. If LLM_PROVIDER is 'waterfall' (or unset): Groq -> Gemini (fastest ~300ms first, failover to Gemini).
    """
    _load_dotenv()
    provider_setting = os.getenv("LLM_PROVIDER", "waterfall").strip().lower()
    if provider_setting == "none":
        return []

    keys = get_configured_keys()
    groq_key = keys["groq"]
    gemini_key = keys["gemini"]

    groq_model = (
        os.getenv("GROQ_MODEL", "").strip() or os.getenv("LLM_MODEL", "").strip() or DEFAULT_MODELS["groq"]
    )
    gemini_model = (
        os.getenv("GEMINI_MODEL", "").strip()
        or os.getenv("LLM_MODEL", "").strip()
        or DEFAULT_MODELS["gemini"]
    )

    if provider_setting == "groq":
        candidates = []
        if groq_key:
            candidates.append(("groq", groq_key, groq_model))
        if gemini_key:
            candidates.append(("gemini", gemini_key, gemini_model))
        return candidates

    if provider_setting == "gemini":
        candidates = []
        if gemini_key:
            candidates.append(("gemini", gemini_key, gemini_model))
        if groq_key:
            candidates.append(("groq", groq_key, groq_model))
        return candidates

    # Default / 'waterfall' / 'auto': try Groq then Gemini
    candidates = []
    if groq_key:
        candidates.append(("groq", groq_key, groq_model))
    if gemini_key:
        candidates.append(("gemini", gemini_key, gemini_model))
    return candidates


def is_available() -> bool:
    """Return True if at least one LLM provider has an API key configured."""
    return len(get_waterfall_providers()) > 0


def clear_cache() -> None:
    """Clear in-memory narrative cache (useful in tests)."""
    with _CACHE_LOCK:
        _NARRATIVE_CACHE.clear()


def compute_cache_key(
    raw_features: dict[str, Any],
    predicted_attack_cat: str,
    risk_score: int,
) -> str:
    """Deterministic hash over flow features, predicted class, and risk score."""
    canonical_items = sorted((str(k), str(v)) for k, v in raw_features.items())
    payload = json.dumps(
        {"features": canonical_items, "class": predicted_attack_cat, "risk": int(risk_score)},
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def _enforce_async_rate_limit(min_interval: float = _RATE_LIMIT_SECONDS) -> None:
    """Enforce minimum interval between outbound LLM requests asynchronously.

    Does NOT block the event loop — yields with await asyncio.sleep so other
    requests (including /ws/stream) continue running.
    """
    global _LAST_CALL_TIMESTAMP
    async with _ASYNC_RATE_LOCK:
        now = time.monotonic()
        elapsed = now - _LAST_CALL_TIMESTAMP
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            await asyncio.sleep(sleep_time)
        _LAST_CALL_TIMESTAMP = time.monotonic()


def _enforce_sync_rate_limit(min_interval: float = _RATE_LIMIT_SECONDS) -> None:
    """Synchronous fallback rate limiter for sync invocations."""
    global _LAST_CALL_TIMESTAMP
    with _SYNC_RATE_LOCK:
        now = time.monotonic()
        elapsed = now - _LAST_CALL_TIMESTAMP
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)
        _LAST_CALL_TIMESTAMP = time.monotonic()


def _build_user_prompt(
    predicted_attack_cat: str,
    confidence: float,
    risk_score: int,
    risk_tier: str,
    review_recommended: bool,
    top_features: list[dict[str, Any]],
) -> str:
    lines = [
        f"Predicted Category: {predicted_attack_cat}",
        f"Confidence Score: {confidence:.1%} ({confidence:.4f})",
        f"Risk Score: {risk_score}/100 (Tier: {risk_tier})",
        f"Review Recommended: {review_recommended}",
        "Top SHAP Contributing Features:",
    ]
    for feat in top_features:
        name = feat.get("name") or feat.get("feature", "unknown")
        val = feat.get("value")
        if val is None:
            val = feat.get("encoded_value", "N/A")
        contrib = feat.get("shap_contribution")
        if contrib is None:
            contrib = feat.get("contribution", 0.0)
        lines.append(f"- {name}: value={val}, contribution={contrib:+.4f}")

    lines.append(
        "\nProvide your output strictly in JSON format with exactly two keys: "
        '"summary" (2-3 sentences) and "recommended_action" (1 sentence).'
    )
    return "\n".join(lines)


def _parse_llm_json(raw_text: str) -> tuple[str, str]:
    """Extract summary and recommended_action from LLM response text."""
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

    try:
        data = json.loads(text)
        summary = str(data.get("summary", "")).strip()
        action = str(data.get("recommended_action", "")).strip()
        if summary and action:
            return summary, action
    except json.JSONDecodeError:
        pass

    summary_match = re.search(r'"summary"\s*:\s*"([^"]+)"', text)
    action_match = re.search(r'"recommended_action"\s*:\s*"([^"]+)"', text)
    summary = summary_match.group(1).strip() if summary_match else text[:300]
    action = (
        action_match.group(1).strip()
        if action_match
        else "Review flow evidence with security operations analyst."
    )
    return summary, action


def generate_builtin_explanation(
    predicted_attack_cat: str,
    confidence: float,
    risk_score: int,
    risk_tier: str,
    review_recommended: bool,
    top_features: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate a deterministic, grounded non-AI explanation from model evidence."""
    feat_phrases = []
    for f in top_features[:3]:
        name = f.get("name") or f.get("feature", "feature")
        val = f.get("value")
        if val is None:
            val = f.get("encoded_value", "N/A")
        contrib = f.get("shap_contribution")
        if contrib is None:
            contrib = f.get("contribution", 0.0)
        direction = "increasing" if contrib >= 0 else "reducing"
        if isinstance(val, float):
            val_str = f"{val:.2f}"
        else:
            val_str = str(val)
        feat_phrases.append(f"{name} ({val_str}, {direction} attack score by {abs(contrib):.2f})")

    features_text = ", ".join(feat_phrases) if feat_phrases else "standard session feature distributions"

    if predicted_attack_cat == "Normal":
        summary = (
            f"Classified as Normal with {confidence:.1%} confidence and {risk_tier} risk ({risk_score}/100). "
            f"Primary factors driving the baseline margin include {features_text}. "
            f"{'Flagged for review due to anomalous baseline patterns.' if review_recommended else 'Traffic characteristics remain within expected baseline bounds.'}"
        )
        action = (
            "Review flow against host and DNS logs for subtle anomalies."
            if review_recommended
            else "Continue routine security monitoring; this prediction does not certify the flow as safe."
        )
    else:
        summary = (
            f"Classified as {predicted_attack_cat} attack with {confidence:.1%} confidence and {risk_tier} risk ({risk_score}/100). "
            f"Key contributing factors driving the attack margin include {features_text}. "
            f"{'Review is recommended under the operational threshold policy.' if review_recommended else 'Attack score is below the operational escalation threshold.'}"
        )
        action = (
            f"Escalate {predicted_attack_cat} detection to security operations for corroboration and investigation."
            if review_recommended
            else "Log detection for trend correlation; immediate escalation optional."
        )

    return {
        "summary": summary,
        "recommended_action": action,
        "provider": "Built-in explanation (Rule-based)",
        "is_builtin": True,
    }


def get_builtin_explanation(scored_result: dict[str, Any]) -> dict[str, Any]:
    """Extract evidence fields from scored result and return a built-in explanation."""
    explanation = scored_result.get("explanation") or {}
    top_features = [
        {
            "name": f.get("feature", "unknown"),
            "value": f.get("encoded_value", 0.0),
            "shap_contribution": f.get("contribution", 0.0),
        }
        for f in explanation.get("features", [])
    ]
    return generate_builtin_explanation(
        predicted_attack_cat=scored_result["predicted_attack_cat"],
        confidence=scored_result["confidence"],
        risk_score=scored_result["risk_score"],
        risk_tier=scored_result.get("risk_level", "medium"),
        review_recommended=scored_result.get("review_recommended", False),
        top_features=top_features,
    )


async def _request_groq_async(
    client: httpx.AsyncClient,
    user_prompt: str,
    api_key: str,
    model: str,
) -> tuple[str, str]:
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "NIDA-SOC/2.0",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    resp = await client.post(url, json=body, headers=headers)
    if resp.status_code == 429:
        raise ProviderQuotaExceeded("Groq rate limit exceeded (HTTP 429)")
    if resp.status_code >= 400:
        raise ProviderError(f"Groq API returned HTTP {resp.status_code}")

    res_data = resp.json()
    content = res_data["choices"][0]["message"]["content"]
    return _parse_llm_json(content)


async def _request_gemini_async(
    client: httpx.AsyncClient,
    user_prompt: str,
    api_key: str,
    model: str,
) -> tuple[str, str]:
    # Key is passed in header to avoid exposure in URLs or HTTP logs
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "NIDA-SOC/2.0",
    }
    body = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    resp = await client.post(url, json=body, headers=headers)
    if resp.status_code == 429:
        raise ProviderQuotaExceeded("Gemini quota/rate limit exceeded (HTTP 429)")
    if resp.status_code >= 400:
        raise ProviderError(f"Gemini API returned HTTP {resp.status_code}")

    res_data = resp.json()
    candidates = res_data.get("candidates", [])
    if not candidates:
        raise ProviderError("No candidates returned from Gemini API")
    content = candidates[0]["content"]["parts"][0]["text"]
    return _parse_llm_json(content)


def _request_groq_sync(
    user_prompt: str,
    api_key: str,
    model: str,
    timeout: float = 6.0,
) -> tuple[str, str]:
    """Synchronous Groq request implementation using urllib.request."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "NIDA-SOC/2.0",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            content = res_data["choices"][0]["message"]["content"]
            return _parse_llm_json(content)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise ProviderQuotaExceeded("Groq HTTP 429") from exc
        raise ProviderError(f"Groq HTTP {exc.code}") from exc


def _request_gemini_sync(
    user_prompt: str,
    api_key: str,
    model: str,
    timeout: float = 6.0,
) -> tuple[str, str]:
    """Synchronous Gemini request implementation using urllib.request."""
    # Key is passed in header to avoid exposure in URLs or HTTP logs
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "NIDA-SOC/2.0",
    }
    body = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            candidates = res_data.get("candidates", [])
            if not candidates:
                raise ProviderError("No candidates returned from Gemini")
            content = candidates[0]["content"]["parts"][0]["text"]
            return _parse_llm_json(content)
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise ProviderQuotaExceeded("Gemini HTTP 429") from exc
        raise ProviderError(f"Gemini HTTP {exc.code}") from exc


async def agenerate_narrative(
    predicted_attack_cat: str,
    confidence: float,
    risk_score: int,
    risk_tier: str,
    review_recommended: bool,
    top_features: list[dict[str, Any]],
    timeout: float = 6.0,
) -> dict[str, str]:
    """Asynchronously generate a grounded narrative with waterfall failover.

    If the primary provider hits rate limits (429) or connection failure,
    it automatically fails over to the secondary provider without blocking
    the FastAPI event loop.
    """
    providers = get_waterfall_providers()
    if not providers:
        return {
            "summary": FALLBACK_SUMMARY,
            "recommended_action": FALLBACK_ACTION,
            "provider": "none",
        }

    user_prompt = _build_user_prompt(
        predicted_attack_cat=predicted_attack_cat,
        confidence=confidence,
        risk_score=risk_score,
        risk_tier=risk_tier,
        review_recommended=review_recommended,
        top_features=top_features,
    )

    attempted_providers: list[str] = []
    async with httpx.AsyncClient(timeout=timeout) as client:
        for idx, (provider, api_key, model) in enumerate(providers):
            attempted_providers.append(provider)
            try:
                await _enforce_async_rate_limit(_RATE_LIMIT_SECONDS)
                if provider == "groq":
                    summary, action = await _request_groq_async(client, user_prompt, api_key, model)
                elif provider == "gemini":
                    summary, action = await _request_gemini_async(client, user_prompt, api_key, model)
                else:
                    continue

                provider_label = f"{provider} ({model})"
                if idx > 0:
                    provider_label += f" [waterfall failover from {providers[0][0]}]"
                return {
                    "summary": summary,
                    "recommended_action": action,
                    "provider": provider_label,
                }
            except Exception as exc:
                # Log safe error without exposing credentials or URLs
                status_desc = type(exc).__name__
                if idx + 1 < len(providers):
                    next_provider = providers[idx + 1][0]
                    logger.warning(
                        "LLM provider '%s' failed (%s). Failing over to '%s' (waterfall)...",
                        provider,
                        status_desc,
                        next_provider,
                    )
                else:
                    logger.warning(
                        "LLM provider '%s' failed (%s). No remaining fallback provider.",
                        provider,
                        status_desc,
                    )

    return {
        "summary": FALLBACK_SUMMARY,
        "recommended_action": FALLBACK_ACTION,
        "provider": "failed: " + ", ".join(attempted_providers),
    }


def generate_narrative(
    predicted_attack_cat: str,
    confidence: float,
    risk_score: int,
    risk_tier: str,
    review_recommended: bool,
    top_features: list[dict[str, Any]],
    timeout: float = 6.0,
) -> dict[str, str]:
    """Synchronous narrative generator with waterfall failover (for sync contexts / tests)."""
    providers = get_waterfall_providers()
    if not providers:
        return {
            "summary": FALLBACK_SUMMARY,
            "recommended_action": FALLBACK_ACTION,
            "provider": "none",
        }

    user_prompt = _build_user_prompt(
        predicted_attack_cat=predicted_attack_cat,
        confidence=confidence,
        risk_score=risk_score,
        risk_tier=risk_tier,
        review_recommended=review_recommended,
        top_features=top_features,
    )

    attempted_providers: list[str] = []
    for idx, (provider, api_key, model) in enumerate(providers):
        attempted_providers.append(provider)
        try:
            _enforce_sync_rate_limit(_RATE_LIMIT_SECONDS)
            if provider == "groq":
                summary, action = _request_groq_sync(user_prompt, api_key, model, timeout=timeout)
            elif provider == "gemini":
                summary, action = _request_gemini_sync(user_prompt, api_key, model, timeout=timeout)
            else:
                continue

            provider_label = f"{provider} ({model})"
            if idx > 0:
                provider_label += f" [waterfall failover from {providers[0][0]}]"
            return {
                "summary": summary,
                "recommended_action": action,
                "provider": provider_label,
            }
        except Exception as exc:
            status_desc = type(exc).__name__
            if idx + 1 < len(providers):
                next_provider = providers[idx + 1][0]
                logger.warning(
                    "Sync LLM provider '%s' failed (%s). Failing over to '%s' (waterfall)...",
                    provider,
                    status_desc,
                    next_provider,
                )
            else:
                logger.warning(
                    "Sync LLM provider '%s' failed (%s). No remaining fallback provider.",
                    provider,
                    status_desc,
                )

    return {
        "summary": FALLBACK_SUMMARY,
        "recommended_action": FALLBACK_ACTION,
        "provider": "failed: " + ", ".join(attempted_providers),
    }


async def aget_flow_narrative(
    raw_features: dict[str, Any],
    scored_result: dict[str, Any],
    timeout: float = 6.0,
) -> dict[str, str]:
    """Retrieve or compute a cached plain-English narrative asynchronously."""
    cache_key = compute_cache_key(
        raw_features=raw_features,
        predicted_attack_cat=scored_result["predicted_attack_cat"],
        risk_score=scored_result["risk_score"],
    )

    with _CACHE_LOCK:
        if cache_key in _NARRATIVE_CACHE:
            return _NARRATIVE_CACHE[cache_key]

    explanation = scored_result.get("explanation") or {}
    top_features = [
        {
            "name": f.get("feature", "unknown"),
            "value": f.get("encoded_value", 0.0),
            "shap_contribution": f.get("contribution", 0.0),
        }
        for f in explanation.get("features", [])
    ]

    narrative = await agenerate_narrative(
        predicted_attack_cat=scored_result["predicted_attack_cat"],
        confidence=scored_result["confidence"],
        risk_score=scored_result["risk_score"],
        risk_tier=scored_result.get("risk_level", "medium"),
        review_recommended=scored_result.get("review_recommended", False),
        top_features=top_features,
        timeout=timeout,
    )

    if narrative.get("summary") != FALLBACK_SUMMARY and not str(narrative.get("provider", "")).startswith(
        "failed:"
    ):
        with _CACHE_LOCK:
            _NARRATIVE_CACHE[cache_key] = narrative

    return narrative


def get_flow_narrative(
    raw_features: dict[str, Any],
    scored_result: dict[str, Any],
    timeout: float = 6.0,
) -> dict[str, str]:
    """Synchronous wrapper for retrieving or computing a cached plain-English narrative."""
    cache_key = compute_cache_key(
        raw_features=raw_features,
        predicted_attack_cat=scored_result["predicted_attack_cat"],
        risk_score=scored_result["risk_score"],
    )

    with _CACHE_LOCK:
        if cache_key in _NARRATIVE_CACHE:
            return _NARRATIVE_CACHE[cache_key]

    explanation = scored_result.get("explanation") or {}
    top_features = [
        {
            "name": f.get("feature", "unknown"),
            "value": f.get("encoded_value", 0.0),
            "shap_contribution": f.get("contribution", 0.0),
        }
        for f in explanation.get("features", [])
    ]

    narrative = generate_narrative(
        predicted_attack_cat=scored_result["predicted_attack_cat"],
        confidence=scored_result["confidence"],
        risk_score=scored_result["risk_score"],
        risk_tier=scored_result.get("risk_level", "medium"),
        review_recommended=scored_result.get("review_recommended", False),
        top_features=top_features,
        timeout=timeout,
    )

    if narrative.get("summary") != FALLBACK_SUMMARY and not str(narrative.get("provider", "")).startswith(
        "failed:"
    ):
        with _CACHE_LOCK:
            _NARRATIVE_CACHE[cache_key] = narrative

    return narrative
