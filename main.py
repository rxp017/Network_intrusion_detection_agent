"""Local research API and deterministic benchmark replay."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

import llm_narrator
from model import ROOT, STRIPPED_COLUMNS, ModelBundle

logger = logging.getLogger("nida")
ARTIFACTS_DIR = Path(os.getenv("NIDA_ARTIFACTS_DIR", str(ROOT / "artifacts")))
REPLAY_CSV = ROOT / "data" / "replay.csv"
MAX_BODY = 256 * 1024
MAX_STREAMS = 8


@asynccontextmanager
async def lifespan(application):
    application.state.bundle = await run_in_threadpool(ModelBundle, ARTIFACTS_DIR)
    application.state.active_streams = 0
    application.state.inference_slots = asyncio.Semaphore(4)
    try:
        replay = pd.read_csv(REPLAY_CSV)
        if replay.empty:
            raise ValueError("Empty replay")
        for row in replay.to_dict("records"):
            application.state.bundle.validate_row(row)
        application.state.replay = replay
    except (OSError, ValueError) as exc:
        logger.warning("Replay unavailable: %s", exc)
        application.state.replay = None
    yield


app = FastAPI(
    title="NIDA | Network Intrusion Detection Agent",
    version="2.0.0",
    description="Validated flow inference, per-flow TreeSHAP and labelled benchmark replay.",
    lifespan=lifespan,
)


class RequestBoundary:
    """Bound chunked and Content-Length bodies before JSON parsing."""

    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.application(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > MAX_BODY:
                return await JSONResponse({"detail": "Request body exceeds 256 KiB"}, 413)(
                    scope, receive, send
                )
            chunks.append(message)
            if not message.get("more_body", False):
                break
        iterator = iter(chunks)

        async def buffered_receive():
            try:
                return next(iterator)
            except StopIteration:
                return await receive()

        await self.application(scope, buffered_receive, send)


app.add_middleware(RequestBoundary)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    # Swagger UI uses a CDN; dashboard and its assets are entirely local.
    if request.url.path not in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
    return response


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def bundle():
    return app.state.bundle


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(ROOT / "dashboard.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_id": bundle().model_id,
        "classes": bundle().classes,
        "mode": "benchmark_replay",
        "replay_available": app.state.replay is not None,
    }


@app.get("/metrics")
def metrics():
    return {"model_id": bundle().model_id, **bundle().evaluation}


@app.get("/limitations")
def limitations():
    return bundle().limitations


@app.get("/schema")
def schema():
    return {
        "numeric": bundle().numeric_cols,
        "categorical": bundle().encoder.categories,
        "required": bundle().required_features,
        "ignored_metadata": list(STRIPPED_COLUMNS),
        "numeric_bounds": [0, 1e15],
        "max_batch_size": 100,
    }


@app.get("/sample")
def sample(category: str = Query("Normal")):
    frame = app.state.replay
    if frame is None:
        raise HTTPException(503, "Replay data unavailable")
    subset = frame.loc[frame.attack_cat == category]
    if subset.empty:
        raise HTTPException(404, "Unknown sample class")
    row = subset.iloc[0].to_dict()
    return {
        "source": "Held-out benchmark sample selected by ground-truth class",
        "true_label": row["attack_cat"],
        "features": {k: v for k, v in row.items() if k not in STRIPPED_COLUMNS},
    }


@app.post("/predict")
async def predict(payload: dict = Body(...), explain: bool = Query(True), narrate: bool = Query(False)):
    try:
        # Resilient unwrap if client passes a previously scored flow result object
        if "explanation" in payload and isinstance(payload.get("explanation"), dict):
            raw = payload["explanation"].get("raw_features")
            if raw and isinstance(raw, dict):
                payload = raw

        # Bound work dispatched to the worker pool; event loop stays responsive.
        async with app.state.inference_slots:
            result = await run_in_threadpool(bundle().score_row, payload, explain or narrate)
        # Generate grounded built-in non-AI explanation derived purely from model verdict & SHAP
        result["builtin_explanation"] = llm_narrator.get_builtin_explanation(result)

        if narrate:
            if not llm_narrator.is_available():
                result["narrative"] = None
                result["narrative_status"] = "not_configured"
            else:
                try:
                    narrative = await llm_narrator.aget_flow_narrative(payload, result)
                    if (
                        narrative
                        and narrative.get("provider") != "none"
                        and not str(narrative.get("provider", "")).startswith("failed:")
                        and narrative.get("summary") != llm_narrator.FALLBACK_SUMMARY
                        and not llm_narrator.has_explicit_verdict_conflict(
                            str(narrative.get("summary", "")),
                            result["predicted_attack_cat"],
                            bundle().classes,
                        )
                    ):
                        # The provider writes prose; model evidence controls the action.
                        result["narrative"] = {
                            **narrative,
                            "recommended_action": result["recommended_action"],
                        }
                        result["narrative_status"] = "ok"
                    else:
                        result["narrative"] = None
                        result["narrative_status"] = "unavailable"
                except Exception as exc:
                    logger.warning("Failed to generate narrative: %s", type(exc).__name__)
                    result["narrative"] = None
                    result["narrative_status"] = "unavailable"
            if not explain and "explanation" in result:
                del result["explanation"]
        return result
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/predict/batch")
async def predict_batch(payload: list[dict] = Body(..., min_length=1, max_length=100)):
    try:
        for row in payload:
            bundle().validate_row(row)
        async with app.state.inference_slots:
            results = await run_in_threadpool(lambda: [bundle().score_row(row, False) for row in payload])
        return {"count": len(results), "results": results}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/explain/{attack_cat}")
def explain_class(attack_cat: str):
    if attack_cat not in bundle().classes:
        raise HTTPException(404, "Unknown attack class")
    return {
        "attack_cat": attack_cat,
        **bundle().explainability,
        "note": "Global gain is shared across classes. POST /predict returns per-flow TreeSHAP.",
    }


def origin_allowed(websocket):
    origin = websocket.headers.get("origin")
    if not origin:  # Command-line clients; this is not an authentication mechanism.
        return True
    parsed = urlparse(origin)
    return parsed.scheme in ("http", "https") and parsed.netloc == websocket.headers.get("host")


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    if not origin_allowed(websocket):
        await websocket.close(code=1008)
        return
    try:
        interval = float(websocket.query_params.get("interval", "0.6"))
        offset = int(websocket.query_params.get("offset", "0"))
        if not 0.1 <= interval <= 3 or offset < 0:
            raise ValueError()
    except ValueError:
        await websocket.close(code=1008)
        return
    category = websocket.query_params.get("category", "all")
    if category != "all" and category not in bundle().classes:
        await websocket.close(code=1008)
        return
    if app.state.active_streams >= MAX_STREAMS:
        await websocket.close(code=1013)
        return
    await websocket.accept()
    frame = app.state.replay
    if frame is None:
        await websocket.send_json({"error": "Replay unavailable; REST inference remains available"})
        await websocket.close(code=1011)
        return
    if category != "all":
        frame = frame.loc[frame.attack_cat == category]
    records = frame.to_dict("records")
    app.state.active_streams += 1
    disconnected = asyncio.Event()

    async def receive_disconnect():
        try:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            disconnected.set()

    receiver = asyncio.create_task(receive_disconnect())
    try:
        cursor = offset
        while not disconnected.is_set():
            row_index = cursor % len(records)
            row = records[row_index]
            features = {k: v for k, v in row.items() if k not in STRIPPED_COLUMNS}
            async with app.state.inference_slots:
                result = await run_in_threadpool(bundle().score_row, features)
            if disconnected.is_set():
                break
            await websocket.send_json(
                {
                    **result,
                    "event_id": f"replay-{int(row['id'])}-{cursor // len(records)}",
                    "row_index": row_index,
                    "next_offset": cursor + 1,
                    "cycle": cursor // len(records),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "benchmark_replay",
                    "true_label": str(row["attack_cat"]),
                    "protocol": str(row["proto"]),
                    "service": str(row["service"]),
                }
            )
            cursor += 1
            try:
                await asyncio.wait_for(disconnected.wait(), timeout=interval)
            except TimeoutError:
                pass
    except (WebSocketDisconnect, OSError):
        pass
    except Exception:
        logger.exception("Replay stream failed")
        try:
            await websocket.close(code=1011)
        except RuntimeError:
            pass
    finally:
        app.state.active_streams -= 1
        receiver.cancel()
        await asyncio.gather(receiver, return_exceptions=True)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("NIDA_HOST", "127.0.0.1"), port=int(os.getenv("NIDA_PORT", "8000")))
