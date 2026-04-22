from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import closing

from app.config import get_settings
from app import storage


class LogStateConsistencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._data_dir = tempfile.TemporaryDirectory()
        os.environ["DATA_DIR"] = self._data_dir.name
        os.environ["GEO_LOOKUP_ENABLED"] = "false"
        os.environ.pop("SCREEN_FLOW_DEBUG", None)
        get_settings.cache_clear()
        self._clear_screen_cache()
        storage.init_db()

    def tearDown(self) -> None:
        self._clear_screen_cache()
        os.environ.pop("SCREEN_FLOW_DEBUG", None)
        get_settings.cache_clear()
        self._data_dir.cleanup()

    def _clear_screen_cache(self) -> None:
        with storage._SCREEN_SNAPSHOT_CACHE_LOCK:
            storage._SCREEN_SNAPSHOT_CACHE.update(
                {"hours": None, "expires_at": 0.0, "updated_at": "", "payload": None}
            )

    def _add_log(self, **overrides: object) -> None:
        payload = {
            "client_ip": "198.51.100.10",
            "destination_host": "example.com",
            "destination_ip": "203.0.113.10",
            "request_host": "example.com",
            "method": "GET",
            "path": "/",
            "query_string": "",
            "user_agent": "Mozilla/5.0",
            "request_headers": "{}",
            "action": "allowed",
            "attack_type": None,
            "attack_detail": None,
            "cve_id": None,
            "rule_category": None,
            "rule_layer": None,
            "matched_field": None,
            "risk_score": None,
            "severity_hint": None,
            "status_code": 200,
            "upstream_status": 200,
            "duration_ms": 12,
            "body_preview": "",
        }
        payload.update(overrides)
        storage.add_log(**payload)

    def _rows(self) -> list[dict]:
        with closing(storage.get_connection()) as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT id, path, alert_status, handled_status, traffic_kind, attack_type, severity
                    FROM request_logs
                    ORDER BY id ASC
                    """
                ).fetchall()
            ]

    def test_root_low_risk_persists_as_whitelist_handled_normal(self) -> None:
        self._add_log(path="/")

        row = self._rows()[0]
        self.assertEqual(row["alert_status"], "whitelist_traffic")
        self.assertEqual(row["handled_status"], "handled")
        self.assertEqual(row["traffic_kind"], "normal")

    def test_favicon_low_risk_persists_as_whitelist_handled_normal(self) -> None:
        self._add_log(path="/favicon.ico")

        row = self._rows()[0]
        self.assertEqual(row["alert_status"], "whitelist_traffic")
        self.assertEqual(row["handled_status"], "handled")
        self.assertEqual(row["traffic_kind"], "normal")

    def test_root_with_strong_attack_signal_is_not_whitelisted(self) -> None:
        self._add_log(path="/", user_agent="sqlmap/1.8")

        row = self._rows()[0]
        self.assertNotEqual(row["alert_status"], "whitelist_traffic")
        self.assertEqual(row["traffic_kind"], "abnormal")

    def test_favicon_with_high_confidence_attack_is_not_whitelisted(self) -> None:
        self._add_log(
            path="/favicon.ico",
            attack_type="sql_injection",
            rule_category="sqli",
            severity_hint="high",
        )

        row = self._rows()[0]
        self.assertNotEqual(row["alert_status"], "whitelist_traffic")
        self.assertEqual(row["traffic_kind"], "abnormal")

    def test_overview_and_screen_disposition_counts_match_database(self) -> None:
        self._add_log(path="/")
        self._add_log(path="/favicon.ico", client_ip="198.51.100.11")
        self._add_log(
            path="/login",
            client_ip="198.51.100.12",
            action="blocked",
            attack_type="brute_force",
            rule_category="auth",
            severity_hint="high",
            status_code=403,
            upstream_status=None,
        )

        rows = self._rows()
        db_whitelist = sum(1 for row in rows if row["alert_status"] == "whitelist_traffic")
        overview = storage.get_overview(hours=24)
        screen = storage.get_screen_snapshot(hours=24)

        self.assertEqual(db_whitelist, 2)
        self.assertEqual(overview["disposition_counts"]["whitelist_traffic"], db_whitelist)
        self.assertEqual(screen["summary"]["disposition_counts"]["whitelist_traffic"], db_whitelist)
        self.assertEqual(
            screen["summary"]["total_handled"],
            sum(screen["summary"]["disposition_counts"].values()),
        )
        self.assertEqual(screen["summary"]["auto_whitelist_count"], db_whitelist)
        self.assertEqual(len(screen["raw_flows"]), 1)
        self.assertEqual(screen["raw_flows"][0]["attack_type"], "brute_force")
        self.assertEqual(screen["top_attack_types"], [{"name": "brute_force", "count": 1}])
        self.assertEqual(storage.list_logs(alerts_only=True)["total"], 1)
        self.assertEqual(storage.list_logs(alert_status="whitelist_traffic")["total"], db_whitelist)

    def test_status_updates_keep_whitelist_handled_normal(self) -> None:
        self._add_log(path="/api/status")
        self._add_log(path="/blocked", action="blocked", attack_type="scanner_probe", status_code=403, upstream_status=None)
        self._add_log(path="/blocked2", action="blocked", attack_type="scanner_probe", status_code=403, upstream_status=None)
        ids = [row["id"] for row in self._rows()]

        storage.update_log_status(ids[0], "whitelist_traffic")
        storage.bulk_update_log_status(ids[1:], "whitelist_traffic")

        rows = self._rows()
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["alert_status"], "whitelist_traffic")
            self.assertEqual(row["handled_status"], "handled")
            self.assertEqual(row["traffic_kind"], "normal")

    def test_screen_keeps_distinct_raw_flows_when_geo_is_unresolved(self) -> None:
        for index in range(1, 51):
            self._add_log(
                path=f"/attack/{index}",
                client_ip=f"8.8.8.{index}",
                action="blocked",
                attack_type="scanner_probe",
                rule_category="scanner",
                severity_hint="high",
                status_code=403,
                upstream_status=None,
            )

        os.environ["SCREEN_FLOW_DEBUG"] = "true"
        get_settings.cache_clear()
        self._clear_screen_cache()
        screen = storage.get_screen_snapshot(hours=24)
        raw_flows = screen["raw_flows"]
        coordinates = {
            (round(float(flow["source_lng"]), 3), round(float(flow["source_lat"]), 3))
            for flow in raw_flows
        }

        self.assertEqual(len(raw_flows), 50)
        self.assertEqual(len({flow["source_ip"] for flow in raw_flows}), 50)
        self.assertGreaterEqual(len(coordinates), 45)
        self.assertTrue(all(flow["geo_resolved"] is False for flow in raw_flows))
        self.assertTrue(all(flow["display_coord_source"] == "pseudo_ip_hash" for flow in raw_flows))
        self.assertGreaterEqual(len({flow["pseudo_tile"] for flow in raw_flows}), 45)
        self.assertGreater(max(float(flow["source_lng"]) for flow in raw_flows) - min(float(flow["source_lng"]) for flow in raw_flows), 120)
        self.assertGreater(len(screen["representative_flows"]), 1)
        self.assertEqual(screen["debug"]["attack_rows_after_filter"], 50)
        self.assertEqual(screen["debug"]["raw_flows_after_dedup"], 50)
        self.assertEqual(screen["debug"]["geo_placeholder_raw_flow_count"], 50)

    def test_screen_zero_data_returns_no_flows(self) -> None:
        screen = storage.get_screen_snapshot(hours=24)

        self.assertEqual(screen["raw_flows"], [])
        self.assertEqual(screen["representative_flows"], [])
        self.assertEqual(screen["globe"]["raw_flows"], [])
        self.assertEqual(screen["globe"]["representative_flows"], [])

    def test_screen_uses_cached_real_geo_for_flow_coordinates(self) -> None:
        geo_rows = [
            ("8.8.8.8", {"label": "United States / California", "country": "美国", "region": "California", "city": "", "source": "remote"}),
            ("1.1.1.1", {"label": "Australia / Queensland", "country": "澳大利亚", "region": "Queensland", "city": "", "source": "remote"}),
            ("9.9.9.9", {"label": "Germany / Berlin", "country": "德国", "region": "Berlin", "city": "", "source": "remote"}),
        ]
        for ip, geo in geo_rows:
            storage.cache_ip_geo(ip, geo)
            self._add_log(
                path=f"/attack/{ip}",
                client_ip=ip,
                action="blocked",
                attack_type="scanner_probe",
                rule_category="scanner",
                severity_hint="high",
                status_code=403,
                upstream_status=None,
            )

        screen = storage.get_screen_snapshot(hours=24)
        raw_flows = screen["raw_flows"]

        self.assertEqual(len(raw_flows), 3)
        self.assertTrue(all(flow["geo_resolved"] is True for flow in raw_flows))
        self.assertEqual({flow["display_coord_source"] for flow in raw_flows}, {"remote"})
        self.assertEqual(len({(round(float(flow["source_lng"]), 1), round(float(flow["source_lat"]), 1)) for flow in raw_flows}), 3)

    def test_screen_china_source_display_label_keeps_province(self) -> None:
        storage.cache_ip_geo(
            "8.8.4.4",
            {
                "label": "China / Zhejiang Province / 杭州",
                "country": "CN",
                "region": "Zhejiang Province",
                "city": "杭州",
                "source": "remote",
            },
        )
        self._add_log(
            path="/attack/china",
            client_ip="8.8.4.4",
            action="blocked",
            attack_type="scanner_probe",
            rule_category="scanner",
            severity_hint="high",
            status_code=403,
            upstream_status=None,
        )

        screen = storage.get_screen_snapshot(hours=24)
        flow = screen["raw_flows"][0]

        self.assertTrue(flow["geo_resolved"])
        self.assertEqual(flow["display_country"], "中国")
        self.assertEqual(flow["source_province"], "浙江")
        self.assertEqual(flow["display_region"], "浙江")
        self.assertEqual(flow["display_city"], "杭州")
        self.assertEqual(flow["display_label"], "中国 · 浙江 · 杭州")
        self.assertAlmostEqual(float(flow["source_lng"]), 120.1551, places=3)
        self.assertAlmostEqual(float(flow["source_lat"]), 30.2741, places=3)


if __name__ == "__main__":
    unittest.main()
