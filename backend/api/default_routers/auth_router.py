"""登录、会话状态与退出接口，以及应用级鉴权中间件。"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.api.error_protocol import build_error_detail, get_request_id
from backend.auth import AuthService, SESSION_COOKIE_NAME


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["authentication"])
PUBLIC_AUTH_PATHS = frozenset(
    {
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/session",
    }
)


class LoginRequest(BaseModel):
    """管理员登录凭据。"""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class SessionResponse(BaseModel):
    """前端判断是否已登录所需的最小会话信息。"""

    authenticated: bool
    username: str | None = None


def _auth_service(request: Request) -> AuthService:
    service = getattr(request.app.state, "auth_service", None)
    if not isinstance(service, AuthService):
        raise RuntimeError("鉴权服务尚未初始化")
    return service


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": build_error_detail(
                code=code,
                message=message,
                request_id=get_request_id(request),
            )
        },
        headers=headers,
    )


@router.post("/login", response_model=SessionResponse)
async def login(payload: LoginRequest, request: Request, response: Response) -> SessionResponse:
    """验证管理员凭据并设置仅服务端可读的签名会话 Cookie。"""
    service = _auth_service(request)
    rate_key = _client_key(request)
    retry_after = service.rate_limiter.retry_after(rate_key)
    if retry_after:
        logger.warning("登录尝试受限 client=%s", request.client.host if request.client else "unknown")
        return _error_response(
            request,
            status_code=429,
            code="AUTH_RATE_LIMITED",
            message="登录失败次数过多，请稍后再试",
            headers={"Retry-After": str(retry_after)},
        )

    if not service.authenticate(payload.username, payload.password):
        retry_after = service.rate_limiter.record_failure(rate_key)
        headers = {"WWW-Authenticate": "Cookie"}
        if retry_after:
            headers["Retry-After"] = str(retry_after)
        logger.warning("登录失败 client=%s", request.client.host if request.client else "unknown")
        return _error_response(
            request,
            status_code=401,
            code="INVALID_CREDENTIALS",
            message="用户名或密码错误",
            headers=headers,
        )

    service.rate_limiter.reset(rate_key)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=service.issue_session(),
        max_age=service.settings.session_ttl_seconds,
        httponly=True,
        secure=service.settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    logger.info("登录成功 client=%s", request.client.host if request.client else "unknown")
    return SessionResponse(authenticated=True, username=service.settings.username)


@router.get("/session", response_model=SessionResponse)
async def session(request: Request, response: Response) -> SessionResponse:
    """返回当前 Cookie 是否对应有效会话。"""
    service = _auth_service(request)
    username = service.verify_session(request.cookies.get(SESSION_COOKIE_NAME))
    response.headers["Cache-Control"] = "no-store"
    return SessionResponse(authenticated=username is not None, username=username)


@router.post("/logout", response_model=SessionResponse)
async def logout(request: Request, response: Response) -> SessionResponse:
    """清除浏览器会话 Cookie；无有效会话时也保持幂等。"""
    service = _auth_service(request)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=service.settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
    return SessionResponse(authenticated=False)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """在路由和静态文件处理前统一拒绝未认证请求。"""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if request.method == "OPTIONS" or request.url.path in PUBLIC_AUTH_PATHS:
            return await call_next(request)

        service = getattr(request.app.state, "auth_service", None)
        if not isinstance(service, AuthService):
            return _error_response(
                request,
                status_code=503,
                code="AUTH_NOT_READY",
                message="鉴权服务尚未就绪",
            )

        username = service.verify_session(request.cookies.get(SESSION_COOKIE_NAME))
        if username is None:
            return _error_response(
                request,
                status_code=401,
                code="AUTHENTICATION_REQUIRED",
                message="请先登录",
                headers={"WWW-Authenticate": "Cookie"},
            )

        request.state.auth_username = username
        return await call_next(request)


__all__ = ["AuthenticationMiddleware", "router"]
