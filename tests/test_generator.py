import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
