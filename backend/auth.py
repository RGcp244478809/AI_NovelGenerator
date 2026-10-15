"""单管理员登录、会话签名与登录限流。"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Mapping


logger = logging.getLogger(__name__)

AUTH_USERNAME_ENV = "NOVEL_GENERATOR_AUTH_USERNAME"
AUTH_PASSWORD_ENV = "NOVEL_GENERATOR_AUTH_PASSWORD"
AUTH_PASSWORD_HASH_ENV = "NOVEL_GENERATOR_AUTH_PASSWORD_HASH"
AUTH_SESSION_SECRET_ENV = "NOVEL_GENERATOR_AUTH_SESSION_SECRET"
AUTH_COOKIE_SECURE_ENV = "NOVEL_GENERATOR_AUTH_COOKIE_SECURE"
AUTH_SESSION_TTL_ENV = "NOVEL_GENERATOR_AUTH_SESSION_TTL_SECONDS"

SESSION_COOKIE_NAME = "novel_generator_session"
DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60
MIN_PASSWORD_LENGTH = 12
MIN_SESSION_SECRET_LENGTH = 32
PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
LOGIN_ATTEMPT_LIMIT = 5

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _parse_boolean(value: str | None, *, default: bool, name: str) -> bool:
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise RuntimeError(f"{name} 必须是 true 或 false")


def hash_password(password: str, *, iterations: int = PASSWORD_HASH_ITERATIONS) -> str:
    """生成可保存到环境变量的 PBKDF2-SHA256 密码摘要。"""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"密码长度不能少于 {MIN_PASSWORD_LENGTH} 个字符")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(
        (
            PASSWORD_HASH_ALGORITHM,
            str(iterations),
            _base64url_encode(salt),
            _base64url_encode(digest),
        )
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    """以恒定时间比较用户输入与 PBKDF2-SHA256 密码摘要。"""
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = encoded_hash.split("$", 3)
        iterations = int(raw_iterations)
        salt = _base64url_decode(raw_salt)
        expected = _base64url_decode(raw_digest)
    except (binascii.Error, ValueError, TypeError):
        return False
    if (
        algorithm != PASSWORD_HASH_ALGORITHM
        or iterations < 100_000
        or iterations > 2_000_000
        or len(salt) < 16
        or len(expected) != hashlib.sha256().digest_size
    ):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


@dataclass(frozen=True, slots=True)
class AuthSettings:
    """运行期鉴权设置；密码与会话密钥永不写入响应或日志。"""

    username: str
    password: str | None
    password_hash: str | None
    session_secret: bytes
    cookie_secure: bool
    session_ttl_seconds: int


def load_auth_settings(environment: Mapping[str, str] | None = None) -> AuthSettings:
    """从环境变量读取并严格校验鉴权设置，缺失凭据时拒绝启动。"""
    env = os.environ if environment is None else environment
    username = env.get(AUTH_USERNAME_ENV, "").strip()
    password = env.get(AUTH_PASSWORD_ENV)
    password_hash = env.get(AUTH_PASSWORD_HASH_ENV)

    if not username:
        raise RuntimeError(f"必须设置 {AUTH_USERNAME_ENV}")
    if len(username) > 128 or any(character.isspace() for character in username):
        raise RuntimeError(f"{AUTH_USERNAME_ENV} 不能包含空白且最多 128 个字符")
    if bool(password) == bool(password_hash):
        raise RuntimeError(
            f"必须且只能设置 {AUTH_PASSWORD_ENV} 或 {AUTH_PASSWORD_HASH_ENV} 其中一个"
        )
    if password is not None and len(password) < MIN_PASSWORD_LENGTH:
        raise RuntimeError(f"{AUTH_PASSWORD_ENV} 长度不能少于 {MIN_PASSWORD_LENGTH} 个字符")
    if password_hash is not None and not verify_password("", password_hash):
        # 空密码不会命中有效摘要；单独解析结构，避免启动时接受损坏的摘要。
        try:
            algorithm, iterations, salt, digest = password_hash.split("$", 3)
            valid_hash = (
                algorithm == PASSWORD_HASH_ALGORITHM
                and 100_000 <= int(iterations) <= 2_000_000
                and len(_base64url_decode(salt)) >= 16
                and len(_base64url_decode(digest)) == hashlib.sha256().digest_size
            )
        except (binascii.Error, ValueError, TypeError):
            valid_hash = False
        if not valid_hash:
            raise RuntimeError(f"{AUTH_PASSWORD_HASH_ENV} 格式不合法")

    raw_secret = env.get(AUTH_SESSION_SECRET_ENV, "")
    if raw_secret and len(raw_secret) < MIN_SESSION_SECRET_LENGTH:
        raise RuntimeError(
            f"{AUTH_SESSION_SECRET_ENV} 长度不能少于 {MIN_SESSION_SECRET_LENGTH} 个字符"
        )
    if raw_secret:
        session_secret = raw_secret.encode("utf-8")
    else:
        session_secret = secrets.token_bytes(32)
        logger.warning(
            "%s 未设置；本次进程将使用临时会话密钥，服务重启后需要重新登录",
            AUTH_SESSION_SECRET_ENV,
        )

    raw_ttl = env.get(AUTH_SESSION_TTL_ENV, str(DEFAULT_SESSION_TTL_SECONDS)).strip()
    try:
        session_ttl = int(raw_ttl)
    except ValueError as exc:
        raise RuntimeError(f"{AUTH_SESSION_TTL_ENV} 必须是整数") from exc
    if not 300 <= session_ttl <= 30 * 24 * 60 * 60:
        raise RuntimeError(f"{AUTH_SESSION_TTL_ENV} 必须位于 300 到 2592000 秒之间")

    return AuthSettings(
        username=username,
        password=password,
        password_hash=password_hash,
        session_secret=session_secret,
        cookie_secure=_parse_boolean(
            env.get(AUTH_COOKIE_SECURE_ENV),
            default=False,
            name=AUTH_COOKIE_SECURE_ENV,
        ),
        session_ttl_seconds=session_ttl,
    )


class LoginRateLimiter:
    """按客户端与用户名限制连续登录失败，降低在线密码猜测风险。"""

    def __init__(
        self,
        *,
        limit: int = LOGIN_ATTEMPT_LIMIT,
        window_seconds: int = LOGIN_ATTEMPT_WINDOW_SECONDS,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = Lock()

    def _recent_failures(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        return [timestamp for timestamp in self._failures.get(key, ()) if timestamp > cutoff]

    def retry_after(self, key: str, *, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            failures = self._recent_failures(key, current)
            if failures:
                self._failures[key] = failures
            else:
                self._failures.pop(key, None)
            if len(failures) < self.limit:
                return 0
            return max(1, int(self.window_seconds - (current - failures[0])))

    def record_failure(self, key: str, *, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            failures = self._recent_failures(key, current)
            failures.append(current)
            self._failures[key] = failures
            if len(failures) < self.limit:
                return 0
            return max(1, int(self.window_seconds - (current - failures[-self.limit])))

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class AuthService:
    """校验管理员凭据并签发、验证无状态会话令牌。"""

    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self.rate_limiter = LoginRateLimiter()
        credential_material = settings.password_hash or hashlib.sha256(
            (settings.password or "").encode("utf-8")
        ).hexdigest()
        # 密码变化会派生出新的签名密钥，使修改凭据后所有旧会话立即失效。
        self._signing_key = hmac.new(
            settings.session_secret,
            f"{settings.username}\0{credential_material}".encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def authenticate(self, username: str, password: str) -> bool:
        username_matches = hmac.compare_digest(username, self.settings.username)
        if self.settings.password_hash is not None:
            password_matches = verify_password(password, self.settings.password_hash)
        else:
            password_matches = hmac.compare_digest(password, self.settings.password or "")
        return username_matches and password_matches

    def issue_session(self, *, now: int | None = None) -> str:
        issued_at = int(time.time() if now is None else now)
        payload = {
            "exp": issued_at + self.settings.session_ttl_seconds,
            "iat": issued_at,
            "sub": self.settings.username,
            "v": 1,
        }
        encoded_payload = _base64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signature = hmac.new(
            self._signing_key,
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return f"{encoded_payload}.{_base64url_encode(signature)}"

    def verify_session(self, token: str | None, *, now: int | None = None) -> str | None:
        if not token or len(token) > 2048:
            return None
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            signature = _base64url_decode(encoded_signature)
            expected_signature = hmac.new(
                self._signing_key,
                encoded_payload.encode("ascii"),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(signature, expected_signature):
                return None
            payload = json.loads(_base64url_decode(encoded_payload))
        except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None

        current = int(time.time() if now is None else now)
        if not isinstance(payload, dict) or set(payload) != {"exp", "iat", "sub", "v"}:
            return None
        if payload.get("v") != 1 or payload.get("sub") != self.settings.username:
            return None
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            return None
        if issued_at > current + 60 or expires_at <= current or expires_at <= issued_at:
            return None
        if expires_at - issued_at != self.settings.session_ttl_seconds:
            return None
        return self.settings.username


def _password_hash_cli() -> int:
    parser = argparse.ArgumentParser(description="AI Novel Generator 鉴权工具")
    parser.add_argument("command", choices=("hash-password",))
    args = parser.parse_args()
    if args.command == "hash-password":
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            parser.error("两次输入的密码不一致")
        try:
            print(hash_password(password))
        except ValueError as exc:
            parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(_password_hash_cli())


__all__ = [
    "AUTH_COOKIE_SECURE_ENV",
    "AUTH_PASSWORD_ENV",
    "AUTH_PASSWORD_HASH_ENV",
    "AUTH_SESSION_SECRET_ENV",
    "AUTH_SESSION_TTL_ENV",
    "AUTH_USERNAME_ENV",
    "AuthService",
    "AuthSettings",
    "LoginRateLimiter",
    "SESSION_COOKIE_NAME",
    "hash_password",
    "load_auth_settings",
    "verify_password",
]
