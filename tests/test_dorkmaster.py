"""
DorkMaster - Comprehensive Test Suite
========================================

Tests for the unified Dork Generator + Hunter tool.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import DorkConfig, DorkBuilder, DorkGenerator, DorkValidator


def get_config():
    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "default_config.json",
    )
    return DorkConfig(config_path)


class TestDorkConfig(unittest.TestCase):
    def setUp(self):
        self.config = get_config()

    def test_all_engines_loaded(self):
        engines = self.config.get_all_engine_ids()
        expected = ["google", "bing", "duckduckgo", "yahoo", "yandex", "baidu", "shodan", "github"]
        for e in expected:
            self.assertIn(e, engines)
        self.assertEqual(len(engines), 8)

    def test_google_operators(self):
        ops = self.config.get_operators("google")
        for expected in ["intitle", "site", "filetype", "inurl", "intext"]:
            self.assertIn(expected, ops)

    def test_filetypes_loaded(self):
        fts = self.config.get_filetypes("google")
        self.assertIn("pdf", fts)
        self.assertGreater(len(fts), 30)

    def test_nonexistent_engine(self):
        self.assertIsNone(self.config.get_engine("nonexistent"))

    def test_boolean_ops(self):
        bools = self.config.get_boolean_ops("google")
        self.assertIn("AND", bools)
        self.assertIn("OR", bools)
        self.assertIn("NOT", bools)


class TestDorkBuilder(unittest.TestCase):
    def setUp(self):
        self.config = get_config()

    def test_google_single_word(self):
        builder = DorkBuilder(self.config, "google")
        self.assertEqual(builder.build_operator_term("intitle", "login"), "intitle:login")
        self.assertEqual(builder.build_operator_term("filetype", "pdf"), "filetype:pdf")

    def test_google_multi_word_auto_quotes(self):
        builder = DorkBuilder(self.config, "google")
        self.assertEqual(builder.build_operator_term("intitle", "admin panel"), 'intitle:"admin panel"')

    def test_site_never_quoted(self):
        builder = DorkBuilder(self.config, "google")
        self.assertEqual(builder.build_operator_term("site", "example.com"), "site:example.com")

    def test_yandex_join(self):
        builder = DorkBuilder(self.config, "yandex")
        result = builder.join_terms(["site:test.com", "mime:pdf"], "AND")
        self.assertEqual(result, "site:test.com && mime:pdf")

    def test_google_negate(self):
        builder = DorkBuilder(self.config, "google")
        self.assertEqual(builder.negate_term("facebook.com"), "-facebook.com")


class TestDorkValidator(unittest.TestCase):
    def setUp(self):
        self.config = get_config()
        self.validator = DorkValidator(self.config)

    def test_valid_dork(self):
        self.assertTrue(self.validator.is_valid("intitle:login", "google"))

    def test_empty_invalid(self):
        self.assertFalse(self.validator.is_valid("", "google"))

    def test_mutually_exclusive(self):
        self.assertFalse(self.validator.is_valid("filetype:pdf ext:doc", "google"))

    def test_too_long(self):
        self.assertFalse(self.validator.is_valid("intitle:" + "a" * 600, "google"))


class TestDorkGenerator(unittest.TestCase):
    def setUp(self):
        self.config = get_config()
        self.gen = DorkGenerator(self.config)

    def test_basic_generation(self):
        result = self.gen.generate(
            engine_id="google",
            keywords=["login", "admin"],
            selected_operators=["intitle"],
        )
        self.assertGreater(len(result["dorks"]), 0)
        self.assertEqual(result["engine"], "google")

    def test_with_filetypes(self):
        result = self.gen.generate(
            engine_id="google",
            keywords=["login"],
            selected_operators=["intitle"],
            selected_filetypes=["php"],
        )
        self.assertGreater(len(result["dorks"]), 0)
        has_ft = any("filetype:php" in d for d in result["dorks"])
        self.assertTrue(has_ft)

    def test_generate_all(self):
        result = self.gen.generate(
            engine_id="google",
            keywords=["login", "admin"],
            selected_operators=["intitle", "inurl"],
            max_results=0,
            shuffle=False,
        )
        self.assertEqual(result["total_generated"], result["total_possible"])

    def test_empty_keywords(self):
        result = self.gen.generate(engine_id="google", keywords=[])
        self.assertEqual(len(result["dorks"]), 0)

    def test_no_duplicates(self):
        result = self.gen.generate(
            engine_id="google",
            keywords=["login", "login"],
            selected_operators=["intitle"],
        )
        self.assertEqual(len(result["dorks"]), len(set(result["dorks"])))

    def test_multi_engine(self):
        for eid in ["bing", "yandex", "shodan", "github", "baidu"]:
            ops = self.config.get_operators(eid)
            op = list(ops.keys())[0] if ops else None
            if op:
                result = self.gen.generate(
                    engine_id=eid,
                    keywords=["test"],
                    selected_operators=[op],
                )
                self.assertGreater(len(result["dorks"]), 0, f"No dorks for {eid}")

    def test_result_structure(self):
        result = self.gen.generate(engine_id="google", keywords=["test"])
        for key in ["dorks", "total_generated", "total_possible", "engine", "engine_name", "warnings"]:
            self.assertIn(key, result)


class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        from app import create_app
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_index(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"DorkMaster", resp.data)

    def test_api_config(self):
        resp = self.client.get("/api/config")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("engines", data)

    def test_api_generate(self):
        resp = self.client.post("/api/generate", json={
            "engine": "google",
            "keywords": ["login"],
            "operators": ["intitle"],
        })
        self.assertEqual(resp.status_code, 200)
        self.assertGreater(len(resp.get_json()["dorks"]), 0)

    def test_api_count(self):
        resp = self.client.post("/api/count", json={
            "engine": "google",
            "keywords": ["login", "admin"],
            "operators": ["intitle", "inurl"],
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["count"], 6)

    def test_api_export_txt(self):
        resp = self.client.post("/api/export", json={
            "dorks": ["intitle:login"],
            "format": "txt",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp.content_type)

    def test_api_export_json(self):
        resp = self.client.post("/api/export", json={
            "dorks": ["intitle:login"],
            "format": "json",
        })
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["generator"], "DorkMaster")

    def test_hunter_engines(self):
        resp = self.client.get("/api/hunter/engines")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("duckduckgo", data["available_free"])

    def test_hunter_export(self):
        resp = self.client.post("/api/hunter/export", json={
            "urls": ["https://example.com"],
            "format": "txt",
        })
        self.assertEqual(resp.status_code, 200)

    def test_scanner_batch(self):
        """Test the scanner batch API returns proper structure."""
        resp = self.client.post("/api/scanner/scan/batch", json={
            "urls": ["http://example.com/page?id=1"],
            "detect_sqli": True,
            "detect_xss": True,
            "max_concurrency": 2,
            "timeout": 5,
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("summary", data)
        self.assertIn("results", data)
        self.assertIn("total_urls", data["summary"])

    def test_scanner_batch_no_urls(self):
        """Test scanner returns error with no URLs."""
        resp = self.client.post("/api/scanner/scan/batch", json={
            "urls": [],
        })
        self.assertEqual(resp.status_code, 400)

    def test_scanner_export_json(self):
        """Test scanner export in JSON format."""
        resp = self.client.post("/api/scanner/export", json={
            "results": [{"url": "http://a.com?x=1", "status": "clean", "findings": []}],
            "summary": {"total_urls": 1, "total_findings": 0, "vuln_counts": {}},
            "format": "json",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.content_type)

    def test_scanner_export_txt(self):
        """Test scanner export in TXT format."""
        resp = self.client.post("/api/scanner/export", json={
            "results": [{"url": "http://a.com?x=1", "status": "clean", "findings": []}],
            "summary": {"total_urls": 1, "total_findings": 0, "vuln_counts": {}},
            "format": "txt",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp.content_type)

    def test_scanner_export_csv(self):
        """Test scanner export in CSV format."""
        resp = self.client.post("/api/scanner/export", json={
            "results": [{"url": "http://a.com?x=1", "status": "clean", "findings": []}],
            "summary": {"total_urls": 1, "total_findings": 0, "vuln_counts": {}},
            "format": "csv",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)


class TestHunterModules(unittest.TestCase):
    def test_free_engine_init(self):
        from hunter.search.free_engine import FreeSearchEngine
        engine = FreeSearchEngine(queries=["test"], engines=["duckduckgo"])
        self.assertEqual(engine._engines, ["duckduckgo"])
        self.assertEqual(engine._queries, ["test"])

    def test_url_validation(self):
        from hunter.search.free_engine import _is_valid_url
        self.assertTrue(_is_valid_url("https://example.com"))
        self.assertFalse(_is_valid_url("https://google.com"))
        self.assertFalse(_is_valid_url("https://facebook.com"))

    def test_key_manager(self):
        from hunter.search.key_manager import KeyManager, KeyExhaustedError
        km = KeyManager(["k1", "k2"])
        self.assertEqual(km.current_key, "k1")
        self.assertEqual(km.alive_count, 2)
        km.rotate("test")
        self.assertEqual(km.alive_count, 1)
        with self.assertRaises(KeyExhaustedError):
            km.rotate("test")

    def test_load_dorks(self):
        from hunter.orchestrator import load_dorks_from_file
        dorks = load_dorks_from_file("dorks.txt")
        self.assertGreater(len(dorks), 0)

    def test_exporter(self):
        from hunter.reporting.exporter import summary_stats
        stats = summary_stats(100, 10)
        self.assertEqual(stats["total_urls_extracted"], 100)
        self.assertEqual(stats["total_dorks_processed"], 10)


if __name__ == "__main__":
    unittest.main()
