from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .auth import TokenValidator
from .clients.graph import GraphClient
from .clients.http import MicrosoftHttpClient
from .clients.intune import IntuneClient
from .compliance import ComplianceService
from .config import Settings, get_settings
from .dependencies import Services
from .devices import DeviceBindingService
from .errors import MDMError
from .logging import configure_logging, request_id_var
from .persistence import Repository, build_repository
from .policy import PolicyService
from .routes import router


class RequestTooLarge(Exception):
    pass


class SecurityMiddleware:
    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                await JSONResponse(
                    {"error": {"code": "invalid_request", "message": "Invalid Content-Length"}},
                    status_code=400,
                )(scope, receive, send)
                return
            if declared > self.max_bytes:
                await JSONResponse(
                    {"error": {"code": "request_too_large", "message": "Request body is too large"}},
                    status_code=413,
                )(scope, receive, send)
                return
        request_id = headers.get(b"x-request-id", b"").decode("ascii", "ignore") or str(uuid.uuid4())
        context_token = request_id_var.set(request_id)
        received = 0
        response_started = False

        async def bounded_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestTooLarge
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                message.setdefault("headers", []).extend(
                    [(b"x-request-id", request_id.encode()), (b"x-content-type-options", b"nosniff")]
                )
            await send(message)

        try:
            await self.app(scope, bounded_receive, tracked_send)
        except RequestTooLarge:
            if response_started:
                raise
            response = JSONResponse(
                {"error": {"code": "request_too_large", "message": "Request body is too large"}},
                status_code=413,
            )
            await response(scope, receive, send)
        finally:
            request_id_var.reset(context_token)


async def build_services(settings: Settings, repository: Repository | None = None) -> Services:
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.request_timeout_seconds, connect=min(5, settings.request_timeout_seconds)),
        follow_redirects=False,
        headers={"User-Agent": "Himmelblau-MDM/0.1"},
    )
    microsoft_http = MicrosoftHttpClient(client, settings.max_response_bytes)
    graph = GraphClient(settings, microsoft_http)
    repository = repository or await build_repository(settings)
    return Services(
        settings=settings,
        httpx_client=client,
        token_validator=TokenValidator(settings, client),
        graph=graph,
        intune=IntuneClient(settings, graph, microsoft_http),
        repository=repository,
        devices=DeviceBindingService(repository),
        policies=PolicyService(graph, repository),
        compliance=ComplianceService(repository),
    )


def create_app(settings: Settings | None = None, injected_services: Services | None = None) -> FastAPI:
    selected_settings = settings or get_settings()
    configure_logging(selected_settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.services = injected_services or await build_services(selected_settings)
        yield
        if not injected_services:
            await app.state.services.close()

    app = FastAPI(
        title="Himmelblau MDM",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(SecurityMiddleware, max_bytes=selected_settings.max_request_bytes)

    @app.exception_handler(MDMError)
    async def mdm_error_handler(_request: Request, exc: MDMError):
        return JSONResponse(
            {"error": {"code": exc.code, "message": exc.message, "retryable": exc.retryable}},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError):
        return JSONResponse(
            {"error": {"code": "invalid_request", "message": "Protocol request validation failed", "details": exc.errors()}},
            status_code=400,
        )

    @app.get("/health")
    async def health():
        return {"ok": True, "service": "himmelblau-mdm", "version": "0.1.0"}

    app.include_router(router)
    return app
