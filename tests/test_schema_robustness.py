"""The service must return a schema-valid body for any input, never crash."""
import json
import random

import pytest
from fastapi.testclient import TestClient

from codeguard.api.app import app
from codeguard.api.schemas import AnalyzeResponse, BatchResponse

client = TestClient(app)

REQUIRED = {"verdict", "risk_score", "categories", "code_language"}


def _check(body: dict) -> None:
    assert REQUIRED <= body.keys()
    AnalyzeResponse(**body)


WEIRD_BODIES = [
    b"",
    b"null",
    b"[]",
    b"{}",
    b'{"code": null}',
    b'{"code": 12345}',
    b'{"code": ["a", "b"]}',
    b'{"code": {"nested": true}}',
    b'{"cod": "typo key"}',
    b"not json at all; rm -rf /tmp/x",
    b"\xff\xfe\x00\x00binary",
    b'{"code": "' + b"A" * 500_000 + b'"}',
    b'{"code": "\\u0000\\u0000"}',
    b"[" * 5000 + b"]" * 5000,
    json.dumps({"code": "(" * 3000 + ")" * 3000}).encode(),
    json.dumps({"code": "x = " + "[" * 400 + "]" * 400}).encode(),
    json.dumps({"code": "def f():\n" + "  " * 200 + "pass"}).encode(),
]


@pytest.mark.parametrize("raw", WEIRD_BODIES, ids=range(len(WEIRD_BODIES)))
def test_analyze_never_invalid(raw):
    r = client.post("/analyze", content=raw, headers={"content-type": "application/json"})
    assert r.status_code == 200
    _check(r.json())


def test_random_fuzz():
    rng = random.Random(1234)
    for _ in range(60):
        n = rng.randint(0, 3000)
        code = "".join(chr(rng.randint(0, 0x2FFF)) for _ in range(n))
        r = client.post("/analyze", json={"code": code})
        assert r.status_code == 200
        _check(r.json())


def test_plain_schema_fields():
    r = client.post("/analyze", json={"code": "print('hello')"})
    body = r.json()
    _check(body)
    assert body["verdict"] in ("allow", "block")
    assert 0.0 <= body["risk_score"] <= 1.0
    assert body["code_language"] == "python"
    assert "X-CodeGuard-Latency-Ms" in r.headers


def test_root_post_alias():
    r = client.post("/", json={"code": "echo hi"})
    _check(r.json())


@pytest.mark.parametrize("payload", [
    {"snippets": [{"id": "a", "code": "print(1)"}, {"id": "b", "code": "ls -la"}]},
    [{"id": 1, "code": "SELECT 1;"}, {"code": "x"}],
    ["print(1)", "echo 2"],
    {"code": "single"},
    {"snippets": "not-a-list"},
])
def test_batch_shapes(payload):
    r = client.post("/analyze/batch", json=payload)
    assert r.status_code == 200
    body = BatchResponse(**r.json())
    for item in body.results:
        _check(item.model_dump())


def test_batch_preserves_ids_and_order():
    payload = {"snippets": [{"id": f"s{i}", "code": f"print({i})"} for i in range(10)]}
    body = client.post("/analyze/batch", json=payload).json()
    assert [x["id"] for x in body["results"]] == [f"s{i}" for i in range(10)]


def test_health():
    r = client.get("/health")
    assert r.json()["status"] == "ok"
