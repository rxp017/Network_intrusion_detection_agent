"""
main.py -- FastAPI demo API serving the models trained by train.py.

Run (after train.py has produced ./artifacts/):
    uvicorn main:app --reload      # development
    python main.py                 # plain uvicorn on 0.0.0.0:8000

The app fails fast at startup if artifacts are missing. /ws/stream
additionally needs UNSW_NB15_testing-set.csv in the working directory.
Requires fastapi >= 0.93 (lifespan). CORS is wide open -- demo only.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Union

import os
import pandas as pd
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import RootModel

from model import ModelBundle

Scalar = Union[str, int, float, bool, None]


class PredictPayload(RootModel[Dict[str, Scalar]]):
    """Arbitrary key-value mapping of feature names to scalar values."""
    pass

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("unsw-api")

ARTIFACTS_DIR = "artifacts"
TEST_CSV = "UNSW_NB15_testing-set.csv"     # /ws/stream only
STREAM_DELAY_SECONDS = 0.4


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load all artifacts once; fail fast with a clear error otherwise."""
    bundle = ModelBundle(artifacts_dir=ARTIFACTS_DIR)
    app.state.bundle = bundle
    logger.info("Model ready -- %d classes: %s", len(bundle.classes),
                ", ".join(bundle.classes))
    logger.info("Held-out test accuracy (class_report.json): %s",
                bundle.class_report.get("accuracy"))

    try:
        app.state.test_df = pd.read_csv(TEST_CSV)
        logger.info("Loaded test set for streaming: %d rows from %s",
                    len(app.state.test_df), TEST_CSV)
    except FileNotFoundError:
        logger.warning("'%s' not found at startup; /ws/stream will be unavailable.",
                       TEST_CSV)
        app.state.test_df = None
    except Exception as exc:
        logger.warning("Failed to load '%s' at startup (%s); /ws/stream will be unavailable.",
                       TEST_CSV, exc)
        app.state.test_df = None

    yield  # nothing to tear down


app = FastAPI(
    title="UNSW-NB15 Intrusion Detection API",
    description="XGBoost attack_cat classifier + IsolationForest anomaly "
                "scorer. POST a raw CSV-style feature row to /predict, or "
                "open /ws/stream to watch the test set flow by.",
    version="1.0.0",
    lifespan=lifespan,
)

# Demo only: allow every origin. allow_credentials stays False because
# credentialed requests cannot be combined with a wildcard origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_bundle() -> ModelBundle:
    return app.state.bundle


@app.get("/", response_class=FileResponse)
def root():
    """Serve the SOC Dashboard if available, else return API endpoint index."""
    if os.path.exists("dashboard.html"):
        return FileResponse("dashboard.html")
    return {"service": "UNSW-NB15 IDS",
            "endpoints": ["/health", "/predict", "/explain/{attack_cat}",
                          "/limitations", "/ws/stream", "/docs"]}


@app.get("/dashboard", response_class=FileResponse)
def dashboard():
    """Serve the SOC dashboard HTML directly."""
    if os.path.exists("dashboard.html"):
        return FileResponse("dashboard.html")
    raise HTTPException(status_code=404, detail="dashboard.html not found")


@app.get("/api")
def api_info():
    """JSON index of available API endpoints."""
    return {"service": "UNSW-NB15 IDS",
            "endpoints": ["/health", "/predict", "/explain/{attack_cat}",
                          "/limitations", "/ws/stream", "/docs"]}


@app.get("/health")
def health():
    return {"status": "ok", "classes": get_bundle().classes}


@app.post("/predict")
def predict(payload: PredictPayload):
    """Body: one raw feature row (same keys/values as a CSV row, minus
    id/label/attack_cat). Returns the shared score_row() result."""
    return get_bundle().score_row(payload.root)


@app.get("/explain/{attack_cat}")
def explain(attack_cat: str):
    data = get_bundle().explainability
    if attack_cat not in data:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown attack_cat '{attack_cat}'. "
                   f"Available: {sorted(data)}")
    return {"attack_cat": attack_cat, "top_features": data[attack_cat]}


@app.get("/limitations")
def limitations():
    """Verbatim contents of limitations.json."""
    return get_bundle().limitations


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    """
    On connect, load the test set and stream it row by row (wrapping back
    to row 0 at the end). Each message is a score_row() result plus
    row_index / timestamp / true_label. A client disconnect ends the loop
    cleanly without crashing the server.
    """
    await websocket.accept()
    df = websocket.app.state.test_df
    if df is None:
        await websocket.send_json(
            {"error": f"'{TEST_CSV}' not found in the working directory; "
                      "streaming is unavailable."})
        await websocket.close(code=1011)
        return

    feature_cols = [c for c in df.columns
                    if c not in ("id", "label", "attack_cat")]
    n_rows = len(df)
    if n_rows == 0:
        await websocket.send_json(
            {"error": "test set is empty; streaming is unavailable"})
        await websocket.close(code=1011)
        return
    logger.info("/ws/stream: client connected, %d rows from %s",
                n_rows, TEST_CSV)

    i = 0
    try:
        while True:
            row = df.iloc[i]
            result = get_bundle().score_row({c: row[c] for c in feature_cols})
            true_label = row.get("attack_cat")
            await websocket.send_json({
                **result,
                "row_index": i,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "true_label": (str(true_label) if pd.notna(true_label)
                               else "unknown"),
            })
            await asyncio.sleep(STREAM_DELAY_SECONDS)
            i = (i + 1) % n_rows            # wrap back to row 0
    except WebSocketDisconnect:
        logger.info("/ws/stream: client disconnected after %d row(s)", i)
    except Exception:                       # never crash the server
        logger.exception("/ws/stream: unexpected error at row %d", i)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)