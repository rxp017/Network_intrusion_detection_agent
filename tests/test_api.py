import pytest
from starlette.websockets import WebSocketDisconnect


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/dashboard",
        "/health",
        "/schema",
        "/metrics",
        "/limitations",
        "/openapi.json",
        "/static/dashboard.js",
        "/static/dashboard.css",
    ],
)
def test_routes(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"


def test_predict_and_batch(client, flow):
    single = client.post("/predict", json=flow)
    assert single.status_code == 200
    batch = client.post("/predict/batch", json=[flow, flow]).json()
    assert batch["count"] == 2
    assert single.json()["class_probabilities"] == batch["results"][0]["class_probabilities"]
    assert "explanation" not in batch["results"][0]


@pytest.mark.parametrize("payload", [{}, {"dur": 1}, [], None, "oops"])
def test_invalid_requests_return_422(client, payload):
    assert client.post("/predict", json=payload).status_code == 422


def test_unknown_field_and_invalid_value(client, flow):
    assert client.post("/predict", json={**flow, "surprise": 4}).status_code == 422
    assert client.post("/predict", json={**flow, "dur": "bad"}).status_code == 422
    assert (
        client.post(
            "/predict", content='{"dur":NaN}', headers={"Content-Type": "application/json"}
        ).status_code
        == 422
    )


def test_batch_size_limits(client, flow):
    assert client.post("/predict/batch", json=[]).status_code == 422
    assert client.post("/predict/batch", json=[flow] * 101).status_code == 422


def test_request_body_limit(client):
    assert client.post("/predict", content=b" " * 262145).status_code == 413


def test_class_endpoints(client):
    assert client.get("/sample?category=Normal").json()["true_label"] == "Normal"
    assert client.get("/sample?category=invalid").status_code == 404
    assert client.get("/explain/Normal").json()["scope"] == "Global model gain"
    assert client.get("/explain/invalid").status_code == 404


def test_websocket_replay_and_resume(client):
    with client.websocket_connect("/ws/stream?category=Generic&interval=0.1") as ws:
        first = ws.receive_json()
        second = ws.receive_json()
    assert first["source"] == "benchmark_replay"
    assert first["true_label"] == "Generic"
    assert first["next_offset"] == 1
    assert second["next_offset"] == 2
    with client.websocket_connect("/ws/stream?category=Generic&offset=1&interval=0.1") as ws:
        resumed = ws.receive_json()
    assert second["event_id"] == resumed["event_id"]
    assert second["class_probabilities"] == resumed["class_probabilities"]


@pytest.mark.parametrize("query", ["interval=0", "interval=nan", "offset=-1", "category=bad"])
def test_bad_websocket_settings(client, query):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/stream?" + query):
            pass


def test_cross_origin_websocket_denied(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/stream", headers={"origin": "https://evil.example"}):
            pass
