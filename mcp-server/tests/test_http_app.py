"""Tests for the starlette wrapper: bearer-token auth + /healthz."""
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from src.http_app import build_http_app


@pytest.fixture
def client():
    # A minimal inner app (we only care about the middleware + healthz).
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def echo(_req):
        return PlainTextResponse("ok")

    inner = Starlette(routes=[Route("/sse", echo, methods=["GET"])])
    app = build_http_app(inner_app=inner, api_key="secret")
    return TestClient(app)


def test_healthz_requires_no_auth(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_sse_without_auth_header_returns_401(client):
    r = client.get("/sse")
    assert r.status_code == 401


def test_sse_with_wrong_bearer_returns_401(client):
    r = client.get("/sse", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_sse_with_correct_bearer_passes_through(client):
    r = client.get("/sse", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200
    assert r.text == "ok"


def test_malformed_authorization_header_returns_401(client):
    r = client.get("/sse", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
