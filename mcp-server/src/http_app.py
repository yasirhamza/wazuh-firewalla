"""Starlette wrapper: bearer-token auth + /healthz route around the FastMCP SSE app."""
import hmac
import logging

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

logger = logging.getLogger(__name__)

# Paths that bypass auth. /healthz is for Docker; no auth allows us to probe
# liveness without embedding the secret in the container image.
_PUBLIC = frozenset({"/healthz"})


class BearerAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_key: str):
        super().__init__(app)
        self._key = api_key

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _PUBLIC:
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            logger.warning("auth_missing path=%s", request.url.path)
            return JSONResponse(
                {"error": "unauthorized", "message": "missing Bearer token"},
                status_code=401,
            )
        presented = auth[len("Bearer ") :]
        if not hmac.compare_digest(presented, self._key):
            logger.warning("auth_bad_key path=%s", request.url.path)
            return JSONResponse(
                {"error": "unauthorized", "message": "invalid token"},
                status_code=401,
            )
        return await call_next(request)


async def _healthz(_request: Request) -> Response:
    return JSONResponse({"status": "ok"})


def build_http_app(inner_app, api_key: str) -> Starlette:
    """Wrap the FastMCP SSE Starlette app with auth middleware and /healthz."""
    app = Starlette(routes=[
        Route("/healthz", _healthz, methods=["GET"]),
        Mount("/", app=inner_app),
    ])
    app.add_middleware(BearerAuthMiddleware, api_key=api_key)
    return app
