"""鉴权核心与 HTTP 边界的回归测试。"""

from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.api.default_routers.auth_router import AuthenticationMiddleware, router
from backend.auth import (
    AUTH_PASSWORD_ENV,
    AUTH_PASSWORD_HASH_ENV,
    AUTH_SESSION_SECRET_ENV,
    AUTH_USERNAME_ENV,
    AuthService,
    AuthSettings,
    LoginRateLimiter,
    SESSION_COOKIE_NAME,
    hash_password,
    load_auth_settings,
    verify_password,
)


TEST_PASSWORD = "correct horse battery staple"


def make_settings(*, password_hash: str | None = None) -> AuthSettings:
    return AuthSettings(
        username="admin",
        password=None if password_hash else TEST_PASSWORD,
        password_hash=password_hash,
        session_secret=b"a-test-session-secret-that-is-long-enough",
        cookie_secure=False,
        session_ttl_seconds=3600,
    )


def make_app() -> FastAPI:
    app = FastAPI()
    app.state.auth_service = AuthService(make_settings())
    app.add_middleware(AuthenticationMiddleware)
    app.include_router(router)

    @app.get("/api/private")
    async def private_endpoint() -> dict[str, bool]:
        return {"ok": True}

    return app


class AuthSettingsTests(unittest.TestCase):
    def test_credentials_are_required(self) -> None:
        with self.assertRaisesRegex(RuntimeError, AUTH_USERNAME_ENV):
            load_auth_settings({})

    def test_plaintext_and_hash_cannot_both_be_set(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "必须且只能设置"):
            load_auth_settings(
                {
                    AUTH_USERNAME_ENV: "admin",
                    AUTH_PASSWORD_ENV: TEST_PASSWORD,
                    AUTH_PASSWORD_HASH_ENV: hash_password(TEST_PASSWORD, iterations=100_000),
                }
            )

    def test_password_hash_round_trip(self) -> None:
        encoded = hash_password(TEST_PASSWORD, iterations=100_000)
        self.assertTrue(verify_password(TEST_PASSWORD, encoded))
        self.assertFalse(verify_password("wrong password", encoded))
        self.assertTrue(AuthService(make_settings(password_hash=encoded)).authenticate("admin", TEST_PASSWORD))

    def test_stable_secret_is_loaded(self) -> None:
        settings = load_auth_settings(
            {
                AUTH_USERNAME_ENV: "admin",
                AUTH_PASSWORD_ENV: TEST_PASSWORD,
                AUTH_SESSION_SECRET_ENV: "0123456789abcdef0123456789abcdef",
            }
        )
        self.assertEqual(settings.session_secret, b"0123456789abcdef0123456789abcdef")


class AuthServiceTests(unittest.TestCase):
    def test_session_round_trip_tamper_and_expiry(self) -> None:
        service = AuthService(make_settings())
        token = service.issue_session(now=1_000)
        self.assertEqual(service.verify_session(token, now=1_001), "admin")
        self.assertIsNone(service.verify_session(f"{token}x", now=1_001))
        self.assertIsNone(service.verify_session(token, now=4_600))

    def test_password_change_invalidates_existing_session(self) -> None:
        original = AuthService(make_settings())
        token = original.issue_session(now=1_000)
        changed = AuthService(
            AuthSettings(
                username="admin",
                password="a different secure password",
                password_hash=None,
                session_secret=original.settings.session_secret,
                cookie_secure=False,
                session_ttl_seconds=3600,
            )
        )
        self.assertIsNone(changed.verify_session(token, now=1_001))

    def test_rate_limiter_resets_after_window(self) -> None:
        limiter = LoginRateLimiter(limit=2, window_seconds=60)
        self.assertEqual(limiter.record_failure("client", now=100), 0)
        self.assertGreater(limiter.record_failure("client", now=101), 0)
        self.assertGreater(limiter.retry_after("client", now=102), 0)
        self.assertEqual(limiter.retry_after("client", now=161), 0)


class AuthHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(make_app())

    def tearDown(self) -> None:
        self.client.close()

    def test_private_routes_require_login(self) -> None:
        response = self.client.get("/api/private")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "AUTHENTICATION_REQUIRED")
        self.assertEqual(self.client.get("/docs").status_code, 401)

    def test_login_session_private_route_and_logout(self) -> None:
        login_response = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": TEST_PASSWORD},
        )
        self.assertEqual(login_response.status_code, 200)
        self.assertIn("HttpOnly", login_response.headers["set-cookie"])
        self.assertIn("SameSite=lax", login_response.headers["set-cookie"])
        self.assertIn(SESSION_COOKIE_NAME, self.client.cookies)

        session_response = self.client.get("/api/auth/session")
        self.assertEqual(session_response.json(), {"authenticated": True, "username": "admin"})
        self.assertEqual(self.client.get("/api/private").json(), {"ok": True})

        logout_response = self.client.post("/api/auth/logout")
        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(self.client.get("/api/private").status_code, 401)

    def test_invalid_login_does_not_create_session(self) -> None:
        response = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_CREDENTIALS")
        self.assertNotIn(SESSION_COOKIE_NAME, self.client.cookies)


if __name__ == "__main__":
    unittest.main()
