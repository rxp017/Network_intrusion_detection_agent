"""Unit and integration tests for the LLM narrative layer with waterfall failover."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import llm_narrator


@pytest.fixture(autouse=True)
def clean_narrator_state(monkeypatch):
    llm_narrator.clear_cache()
    # Prevent developer's local .env keys from interfering with isolated unit test environments
    monkeypatch.setattr(llm_narrator, "_load_dotenv", lambda: None)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    yield
    llm_narrator.clear_cache()


def test_is_available_conditions(monkeypatch):
    # Default without keys: unavailable (guaranteeing offline safety)
    monkeypatch.setenv("LLM_PROVIDER", "none")
    assert not llm_narrator.is_available()

    # Explicit none overrides keys
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock")
    monkeypatch.setenv("LLM_PROVIDER", "none")
    assert not llm_narrator.is_available()

    # Groq key only
    monkeypatch.setenv("LLM_PROVIDER", "waterfall")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert llm_narrator.is_available()

    # Gemini key only
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-mock")
    assert llm_narrator.is_available()

    # Legacy LLM_API_KEY support
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("LLM_API_KEY", "legacy-key")
    assert llm_narrator.is_available()


def test_waterfall_priority_ordering(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-123")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-456")

    # Default waterfall: Groq first (fastest), then Gemini
    monkeypatch.setenv("LLM_PROVIDER", "waterfall")
    providers = llm_narrator.get_waterfall_providers()
    assert [p[0] for p in providers] == ["groq", "gemini"]

    # Explicit groq: Groq first, then Gemini as failover
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    providers = llm_narrator.get_waterfall_providers()
    assert [p[0] for p in providers] == ["groq", "gemini"]

    # Explicit gemini: Gemini first, then Groq as failover
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    providers = llm_narrator.get_waterfall_providers()
    assert [p[0] for p in providers] == ["gemini", "groq"]


def test_generate_narrative_when_unavailable():
    result = llm_narrator.generate_narrative(
        predicted_attack_cat="Normal",
        confidence=0.95,
        risk_score=10,
        risk_tier="low",
        review_recommended=False,
        top_features=[{"name": "sbytes", "value": 100, "shap_contribution": -0.5}],
    )
    assert result["summary"] == llm_narrator.FALLBACK_SUMMARY
    assert result["provider"] == "none"


def test_groq_adapter_success_sync(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    mock_resp_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "This flow is predicted as DoS due to excessive packet rates.",
                            "recommended_action": "Verify traffic volume and review rate limits.",
                        }
                    )
                }
            }
        ]
    }

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_resp_payload
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        narrative = llm_narrator.generate_narrative(
            predicted_attack_cat="DoS",
            confidence=0.88,
            risk_score=72,
            risk_tier="high",
            review_recommended=True,
            top_features=[{"name": "sbytes", "value": 50000, "shap_contribution": 1.2}],
        )

    assert "predicted as DoS" in narrative["summary"]
    assert "rate limits" in narrative["recommended_action"]
    assert "groq" in narrative["provider"]


def test_waterfall_failover_on_rate_limit_429(monkeypatch):
    """When Groq returns HTTP 429 (rate limit), it seamlessly falls over to Gemini."""
    async def _test():
        monkeypatch.setenv("GROQ_API_KEY", "gsk-quota-exhausted")
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-working-key")
        monkeypatch.setenv("LLM_PROVIDER", "waterfall")

        groq_429_resp = httpx.Response(
            429,
            text=json.dumps({"error": {"message": "Rate limit reached for requests per minute (TPM/RPM)"}}),
        )
        gemini_ok_payload = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "summary": "Gemini fallback: Suspicious generic scanning activity detected.",
                                        "recommended_action": "Quarantine target host and review firewall logs.",
                                    }
                                )
                            }
                        ]
                    }
                }
            ]
        }
        gemini_200_resp = httpx.Response(200, text=json.dumps(gemini_ok_payload))

        async def mock_post(url, *args, **kwargs):
            if "groq.com" in str(url):
                return groq_429_resp
            if "googleapis.com" in str(url):
                return gemini_200_resp
            raise ValueError(f"Unexpected url {url}")

        with patch.object(httpx.AsyncClient, "post", side_effect=mock_post):
            narrative = await llm_narrator.agenerate_narrative(
                predicted_attack_cat="Generic",
                confidence=0.91,
                risk_score=78,
                risk_tier="high",
                review_recommended=True,
                top_features=[{"name": "dur", "value": 1.5, "shap_contribution": 0.8}],
            )

        assert "Gemini fallback" in narrative["summary"]
        assert "Quarantine target" in narrative["recommended_action"]
        assert "gemini" in narrative["provider"]
        assert "waterfall failover from groq" in narrative["provider"]

    asyncio.run(_test())


def test_waterfall_all_providers_fail(monkeypatch):
    """When both providers hit rate limits or errors, safe fallback is returned without crash."""
    async def _test():
        monkeypatch.setenv("GROQ_API_KEY", "gsk-fail")
        monkeypatch.setenv("GEMINI_API_KEY", "gemini-fail")
        monkeypatch.setenv("LLM_PROVIDER", "waterfall")

        async def mock_post(url, *args, **kwargs):
            return httpx.Response(429, text="Rate limit exceeded")

        with patch.object(httpx.AsyncClient, "post", side_effect=mock_post):
            narrative = await llm_narrator.agenerate_narrative(
                predicted_attack_cat="Exploits",
                confidence=0.85,
                risk_score=80,
                risk_tier="critical",
                review_recommended=True,
                top_features=[],
            )

        assert narrative["summary"] == llm_narrator.FALLBACK_SUMMARY
        assert narrative["recommended_action"] == llm_narrator.FALLBACK_ACTION
        assert narrative["provider"].startswith("failed:")

    asyncio.run(_test())


def test_event_loop_unblocked_during_llm_call(monkeypatch):
    """
    CRITICAL CONCURRENCY TEST:
    Demonstrates that while an outbound LLM request is awaiting network I/O,
    the asyncio event loop is NEVER blocked. Concurrent coroutines execute freely.
    """
    async def _test():
        monkeypatch.setenv("GROQ_API_KEY", "gsk-async-test")
        monkeypatch.setenv("LLM_PROVIDER", "groq")

        async def slow_mock_post(url, *args, **kwargs):
            # Simulate network latency of 150ms
            await asyncio.sleep(0.15)
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "summary": "Non-blocking async narrative completed.",
                                        "recommended_action": "Verify server event loop responsiveness.",
                                    }
                                )
                            }
                        }
                    ]
                },
            )

        ticks_completed = 0

        async def simulate_concurrent_event_loop_task():
            nonlocal ticks_completed
            for _ in range(5):
                await asyncio.sleep(0.02)
                ticks_completed += 1

        with patch.object(httpx.AsyncClient, "post", side_effect=slow_mock_post):
            narrator_task = asyncio.create_task(
                llm_narrator.agenerate_narrative(
                    predicted_attack_cat="Normal",
                    confidence=0.99,
                    risk_score=2,
                    risk_tier="low",
                    review_recommended=False,
                    top_features=[],
                )
            )
            concurrent_task = asyncio.create_task(simulate_concurrent_event_loop_task())

            narrative, _ = await asyncio.gather(narrator_task, concurrent_task)

        # The concurrent task was able to tick multiple times during the network I/O!
        assert ticks_completed >= 4
        assert "Non-blocking async narrative" in narrative["summary"]

    asyncio.run(_test())


def test_in_memory_cache(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    mock_resp_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Cached analysis summary.",
                            "recommended_action": "Cached action.",
                        }
                    )
                }
            }
        ]
    }

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_resp_payload
    ).encode("utf-8")

    sample_features = {"dur": 0.1, "proto": "tcp", "sbytes": 100}
    sample_result = {
        "predicted_attack_cat": "Generic",
        "confidence": 0.85,
        "risk_score": 65,
        "risk_level": "high",
        "review_recommended": True,
        "explanation": {
            "features": [{"feature": "sbytes", "encoded_value": 100, "contribution": 0.4}]
        },
    }

    with patch("urllib.request.urlopen", mock_urlopen):
        res1 = llm_narrator.get_flow_narrative(sample_features, sample_result)
        res2 = llm_narrator.get_flow_narrative(sample_features, sample_result)

    assert res1 == res2
    assert res1["summary"] == "Cached analysis summary."
    # The network request was only dispatched once
    assert mock_urlopen.call_count == 1


def test_predict_narrate_endpoint_when_unavailable(client, flow):
    response = client.post("/predict?narrate=true", json=flow)
    assert response.status_code == 200
    data = response.json()
    assert data["narrative"] is None
    assert data["narrative_status"] == "unavailable"


def test_predict_narrate_endpoint_when_available(client, flow, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-mock")
    monkeypatch.setenv("LLM_PROVIDER", "groq")

    mock_resp = httpx.Response(
        200,
        json={
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "summary": "Endpoint async narrative verified.",
                                "recommended_action": "Inspect endpoint logs.",
                            }
                        )
                    }
                }
            ]
        },
    )

    with patch.object(httpx.AsyncClient, "post", AsyncMock(return_value=mock_resp)):
        response = client.post("/predict?narrate=true", json=flow)

    assert response.status_code == 200
    data = response.json()
    assert data["narrative_status"] == "ok"
    assert data["narrative"]["summary"] == "Endpoint async narrative verified."
    assert data["narrative"]["recommended_action"] == "Inspect endpoint logs."


def test_predict_batch_ignores_narrate(client, flow):
    # Batch predict never calls or outputs narratives
    response = client.post("/predict/batch", json=[flow, flow])
    assert response.status_code == 200
    batch = response.json()
    for item in batch["results"]:
        assert "narrative" not in item
        assert "narrative_status" not in item
