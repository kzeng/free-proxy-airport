import tempfile
import unittest
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
    def test_infrastructure_failure_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "clash.yaml"
            output.write_text("previous valid subscription", encoding="utf-8")
            with (
                patch.object(generator, "OUTPUT_PATH", output),
                patch.object(generator, "collect_proxies", return_value=(1, [{"name": "node"}])),
                patch.object(generator, "benchmark_proxies", side_effect=RuntimeError("Mihomo unavailable")),
                patch.object(generator, "load_existing_metrics") as load_existing,
            ):
                with self.assertRaisesRegex(RuntimeError, "Mihomo unavailable"):
                    generator.main()
            self.assertEqual(output.read_text(encoding="utf-8"), "previous valid subscription")
            load_existing.assert_not_called()


if __name__ == "__main__":
    unittest.main()
