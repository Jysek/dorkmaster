"""
DorkMaster - Comprehensive Test Suite
========================================

Tests for the unified Dork Generator + Hunter + Scanner tool.
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

    def test_vuln_params_loaded(self):
        vp = self.config.vuln_params
        self.assertIn("patterns", vp)
        self.assertIn("generic", vp["patterns"])
        self.assertIn("php", vp["patterns"])
        self.assertIn("aspx", vp["patterns"])
        # Check specific patterns exist
        generic = vp["patterns"]["generic"]
        self.assertIn(".php?id=1", generic)
        self.assertIn(".aspx?pageid=", generic)

    def test_vuln_params_php_patterns(self):
        vp = self.config.vuln_params
        php = vp["patterns"]["php"]
        self.assertIn("index.php?id=", php)
        self.assertGreater(len(php), 10)

    def test_vuln_params_aspx_patterns(self):
        vp = self.config.vuln_params
        aspx = vp["patterns"]["aspx"]
        self.assertIn("design1.aspx?pageid=", aspx)


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

    def test_vuln_params_generation(self):
        """Test that vuln_params generates inurl: dorks."""
        result = self.gen.generate(
            engine_id="google",
            keywords=["admin"],
            selected_operators=[],
            selected_vuln_params=[".php?id=1", "index.php?id="],
        )
        self.assertGreater(len(result["dorks"]), 0)
        has_inurl = any("inurl:" in d for d in result["dorks"])
        self.assertTrue(has_inurl, "Should contain inurl: terms from vuln_params")

    def test_vuln_params_with_operators(self):
        """Test vuln_params combined with operators."""
        result = self.gen.generate(
            engine_id="google",
            keywords=["login"],
            selected_operators=["intitle"],
            selected_vuln_params=[".php?id="],
        )
        self.assertGreater(len(result["dorks"]), 0)
        # Should have: inurl + keyword, inurl + intitle + keyword, intitle + keyword
        has_both = any("inurl:" in d and "intitle:" in d for d in result["dorks"])
        self.assertTrue(has_both, "Should have dorks combining inurl and intitle")

    def test_vuln_params_empty(self):
        """Empty vuln_params should not break generation."""
        result = self.gen.generate(
            engine_id="google",
            keywords=["test"],
            selected_operators=["intitle"],
            selected_vuln_params=[],
        )
        self.assertGreater(len(result["dorks"]), 0)


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
        self.assertIn("vuln_params", data)

    def test_api_config_has_vuln_params(self):
        resp = self.client.get("/api/config")
        data = resp.get_json()
        self.assertIn("vuln_params", data)
        self.assertIn("patterns", data["vuln_params"])

    def test_api_generate(self):
        resp = self.client.post("/api/generate", json={
            "engine": "google",
            "keywords": ["login"],
            "operators": ["intitle"],
        })
        self.assertEqual(resp.status_code, 200)
        self.assertGreater(len(resp.get_json()["dorks"]), 0)

    def test_api_generate_with_vuln_params(self):
        resp = self.client.post("/api/generate", json={
            "engine": "google",
            "keywords": ["admin"],
            "operators": [],
            "vuln_params": [".php?id=1"],
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreater(len(data["dorks"]), 0)
        self.assertTrue(any("inurl:" in d for d in data["dorks"]))

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
        self.assertIn("has_api_keys", data)
        self.assertIn("proxy_enabled", data)

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

    def test_scanner_batch_with_proxy(self):
        """Test scanner batch API accepts use_proxy parameter."""
        resp = self.client.post("/api/scanner/scan/batch", json={
            "urls": ["http://example.com/page?id=1"],
            "detect_sqli": True,
            "detect_xss": True,
            "max_concurrency": 2,
            "timeout": 5,
            "use_proxy": False,
        })
        self.assertEqual(resp.status_code, 200)

    def test_scanner_export_json(self):
        resp = self.client.post("/api/scanner/export", json={
            "results": [{"url": "http://a.com?x=1", "status": "clean", "findings": []}],
            "summary": {"total_urls": 1, "total_findings": 0, "vuln_counts": {}},
            "format": "json",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp.content_type)

    def test_scanner_export_txt(self):
        resp = self.client.post("/api/scanner/export", json={
            "results": [{"url": "http://a.com?x=1", "status": "clean", "findings": []}],
            "summary": {"total_urls": 1, "total_findings": 0, "vuln_counts": {}},
            "format": "txt",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp.content_type)

    def test_scanner_export_csv(self):
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

    def test_free_engine_with_proxy(self):
        from hunter.search.free_engine import FreeSearchEngine
        engine = FreeSearchEngine(
            queries=["test"],
            engines=["duckduckgo"],
            proxies=["http://proxy1:8080", "socks5://proxy2:1080"],
        )
        self.assertEqual(len(engine._proxies), 2)

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

    def test_key_manager_empty_keys_error(self):
        from hunter.search.key_manager import KeyManager
        with self.assertRaises(ValueError):
            KeyManager([])

    def test_key_manager_filters_empty_strings(self):
        from hunter.search.key_manager import KeyManager
        with self.assertRaises(ValueError):
            KeyManager(["", "  ", ""])

    def test_load_dorks(self):
        from hunter.orchestrator import load_dorks_from_file
        dorks = load_dorks_from_file("dorks.txt")
        self.assertGreater(len(dorks), 0)

    def test_exporter(self):
        from hunter.reporting.exporter import summary_stats
        stats = summary_stats(100, 10)
        self.assertEqual(stats["total_urls_extracted"], 100)
        self.assertEqual(stats["total_dorks_processed"], 10)

    def test_api_engine_with_proxy(self):
        """Test that SearchEngine accepts proxies parameter."""
        from hunter.search.engine import SearchEngine
        from hunter.config import SerperConfig

        config = SerperConfig()
        config.api_keys = ["test_key"]
        engine = SearchEngine(config, proxies=["http://proxy:8080"])
        self.assertEqual(len(engine._proxies), 1)

    def test_api_engine_proxy_rotation(self):
        """Test proxy rotation in SearchEngine."""
        from hunter.search.engine import SearchEngine
        from hunter.config import SerperConfig

        config = SerperConfig()
        config.api_keys = ["test_key"]
        engine = SearchEngine(config, proxies=["http://p1:80", "http://p2:80"])
        p1 = engine._get_proxy()
        p2 = engine._get_proxy()
        self.assertNotEqual(p1, p2)


if __name__ == "__main__":
    unittest.main()
