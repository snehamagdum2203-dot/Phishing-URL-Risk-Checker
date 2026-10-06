import unittest

from app import app


class PhishingURLCheckerTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_high_risk_url(self):
        response = self.client.post(
            "/api/v1/check",
            json={"url": "http://192.0.2.1/verify-account"},
        )
        result = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(result["risk_level"], "High")
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertTrue(result["reasons"])

    def test_missing_url_returns_error(self):
        response = self.client.post("/api/v1/check", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_unsupported_scheme_returns_error(self):
        response = self.client.post(
            "/api/v1/check",
            json={"url": "ftp://example.com"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_non_json_request_returns_error(self):
        response = self.client.post(
            "/api/v1/check",
            data="url=example",
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 415)
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()