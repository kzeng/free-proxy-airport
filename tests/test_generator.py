import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import requests

import generator


class MihomoReleaseTests(unittest.TestCase):
    @patch("generator.platform.machine", return_value="x86_64")
    @patch("generator.platform.system", return_value="Linux")
    @patch("generator.requests.get")
    def test_selects_compatible_linux_asset(self, get, _system, _machine):
        get.return_value.json.return_value = {
            "tag_name": "v1",
            "assets": [
                {"name": "mihomo-linux-amd64-v1.gz", "browser_download_url": "https://example.org/normal.gz"},
                {"name": "mihomo-linux-amd64-compatible-v1.gz", "browser_download_url": "https://example.org/compatible.gz"},
            ],
        }
        with patch.dict("generator.os.environ", {"GITHUB_TOKEN": "test-token"}):
            self.assertEqual(generator.select_mihomo_asset(), "https://example.org/compatible.gz")
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"], "Bearer test-token")

    @patch("generator.requests.get")
    def test_api_http_error_is_not_reported_as_missing_asset(self, get):
        get.return_value.raise_for_status.side_effect = requests.HTTPError("403 rate limit")
        with self.assertRaisesRegex(requests.HTTPError, "403 rate limit"):
            generator.select_mihomo_asset()

    @patch("generator.requests.get")
    def test_unexpected_api_response_is_not_reported_as_missing_asset(self, get):
        get.return_value.json.return_value = {"message": "API rate limit exceeded"}
        with self.assertRaisesRegex(RuntimeError, "no asset list"):
            generator.select_mihomo_asset()

    @patch("generator.platform.machine", return_value="x86_64")
    @patch("generator.platform.system", return_value="Linux")
    @patch("generator.requests.get")
    def test_asset_mismatch_lists_available_names(self, get, _system, _machine):
        get.return_value.json.return_value = {
            "tag_name": "v2",
            "assets": [{"name": "mihomo-linux-amd64-v2.tar.zst"}],
        }
        with self.assertRaisesRegex(RuntimeError, "v2.*mihomo-linux-amd64-v2.tar.zst"):
            generator.select_mihomo_asset()


class BenchmarkFailureTests(unittest.TestCase):
    def assert_keeps_output(self, candidates, benchmark_result):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "clash.yaml"
            output.write_text("previous valid subscription", encoding="utf-8")
            with (
                patch.object(generator, "OUTPUT_PATH", output),
                patch.object(generator, "collect_proxies", return_value=(1, candidates)),
                patch.object(generator, "benchmark_proxies", return_value=benchmark_result) as benchmark,
            ):
                with self.assertRaises(RuntimeError):
                    generator.main()
            self.assertEqual(output.read_text(encoding="utf-8"), "previous valid subscription")
            return benchmark

    def test_empty_sources_do_not_publish_direct_fallback(self):
        self.assert_keeps_output([], []).assert_not_called()

    def test_no_live_nodes_do_not_publish_stale_fallback(self):
        self.assert_keeps_output([{"name": "node"}], []).assert_called_once()

    def test_infrastructure_failure_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "clash.yaml"
            output.write_text("previous valid subscription", encoding="utf-8")
            with (
                patch.object(generator, "OUTPUT_PATH", output),
                patch.object(generator, "collect_proxies", return_value=(1, [{"name": "node"}])),
                patch.object(generator, "benchmark_proxies", side_effect=RuntimeError("Mihomo unavailable")),
            ):
                with self.assertRaisesRegex(RuntimeError, "Mihomo unavailable"):
                    generator.main()
            self.assertEqual(output.read_text(encoding="utf-8"), "previous valid subscription")


class PublicationValidationTests(unittest.TestCase):
    def setUp(self):
        self.config = generator.build_config([
            generator.ProxyMetric(
                proxy={"name": "node", "type": "ss", "server": "127.0.0.1", "port": 443},
                latency=100,
                region="OTHER",
                health_score=0.1,
            )
        ])

    def test_valid_fresh_subscription(self):
        generator.validate_config(self.config)

    def test_rejects_stale_subscription(self):
        self.config["generated-at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        with self.assertRaisesRegex(RuntimeError, "stale"):
            generator.validate_config(self.config)

    def test_rejects_direct_only_subscription(self):
        self.config["proxies"] = [{"name": "DIRECT-FALLBACK", "type": "direct"}]
        with self.assertRaisesRegex(RuntimeError, "non-proxy fallback"):
            generator.validate_config(self.config)

    def test_low_latency_routing_and_legacy_alias(self):
        groups = {group["name"]: group for group in self.config["proxy-groups"]}
        self.assertEqual(groups["LOW-LATENCY-POOL"]["type"], "url-test")
        self.assertEqual(groups["AI-POOL"]["proxies"], ["LOW-LATENCY-POOL"])
        self.assertIn("DOMAIN-SUFFIX,openai.com,LOW-LATENCY-POOL", self.config["rules"])


class RepeatedProbeTests(unittest.TestCase):
    def response(self, latency):
        response = Mock(status_code=200)
        response.json.return_value = {"delay": latency}
        return response

    @patch("generator.time.sleep")
    @patch("generator.requests.get")
    def test_two_successes_are_required_and_median_latency_used(self, get, _sleep):
        get.side_effect = [self.response(100), self.response(300)]
        proxy = {"name": "test", "type": "ss"}
        metric = generator.test_single_proxy("http://localhost", proxy)
        self.assertIsNotNone(metric)
        self.assertEqual(metric.latency, 200)
        self.assertEqual(get.call_count, 2)

    @patch("generator.time.sleep")
    @patch("generator.requests.get")
    def test_one_failure_then_two_successes(self, get, _sleep):
        get.side_effect = [requests.Timeout(), self.response(120), self.response(180)]
        metric = generator.test_single_proxy("http://localhost", {"name": "test"})
        self.assertEqual(metric.latency, 150)
        self.assertAlmostEqual(metric.health_score, generator.health_score(150, "OTHER", 2 / 3))

    @patch("generator.time.sleep")
    @patch("generator.requests.get")
    def test_two_failures_reject_node(self, get, _sleep):
        get.side_effect = [requests.Timeout(), requests.Timeout()]
        self.assertIsNone(generator.test_single_proxy("http://localhost", {"name": "test"}))
        self.assertEqual(get.call_count, 2)

    def test_latency_and_success_rate_dominate_region(self):
        self.assertGreater(generator.health_score(100, "OTHER", 1), generator.health_score(1500, "HK", 1))
        self.assertGreater(generator.health_score(300, "HK", 1), generator.health_score(300, "HK", 2 / 3))


class MihomoStartupTests(unittest.TestCase):
    @patch("generator.subprocess.run")
    def test_preflight_error_reports_engine_output_without_password(self, run):
        run.return_value = Mock(returncode=1, stdout="", stderr="invalid password secret-pass")
        with tempfile.TemporaryDirectory() as directory:
            ok, detail = generator.check_benchmark_config(
                Path("mihomo"), Path(directory),
                [{"name": "test", "type": "ss", "server": "example.org", "port": 443, "password": "secret-pass"}],
                9090,
            )
        self.assertFalse(ok)
        self.assertIn("invalid password", detail)
        self.assertNotIn("secret-pass", detail)

    def test_error_log_redacts_node_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "mihomo.log"
            log.write_text("failed for uuid secret-uuid and password secret-pass", encoding="utf-8")
            summary = generator.engine_log_summary(
                log, [{"uuid": "secret-uuid", "password": "secret-pass"}]
            )
            self.assertNotIn("secret-uuid", summary)
            self.assertNotIn("secret-pass", summary)
            self.assertIn("***", summary)

    @patch("generator.check_benchmark_config")
    def test_invalid_node_is_isolated_before_start(self, check):
        good = {"name": "good", "type": "ss", "server": "a", "port": 443}
        bad = {"name": "bad", "type": "ss", "server": "b", "port": 443}
        check.side_effect = lambda _engine, _dir, items, _port: (
            (False, "invalid node") if bad in items else (True, "")
        )
        result = generator.filter_invalid_benchmark_proxies(Path("mihomo"), Path("."), [good, bad], 9090)
        self.assertEqual(result, [good])

    @patch("generator.check_benchmark_config")
    def test_engine_failure_does_not_drop_all_nodes(self, check):
        check.return_value = (False, "engine cannot start")
        with self.assertRaisesRegex(RuntimeError, "empty benchmark config"):
            generator.filter_invalid_benchmark_proxies(Path("mihomo"), Path("."), [{"name": "good"}], 9090)

    def test_controller_error_includes_exit_code_and_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "mihomo.log"
            log.write_text("invalid proxy configuration", encoding="utf-8")
            process = Mock(returncode=1)
            process.poll.return_value = 1
            with self.assertRaisesRegex(RuntimeError, "(?s)exit 1.*invalid proxy configuration"):
                generator.wait_for_controller("http://localhost", process, log, [])


if __name__ == "__main__":
    unittest.main()
