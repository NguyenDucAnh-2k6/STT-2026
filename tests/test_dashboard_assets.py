"""Regression for stale module imports without running a browser or backend."""
import tempfile
import unittest
from pathlib import Path

from dashboard.backend.assets import DashboardAssets


class DashboardAssetTests(unittest.IsolatedAsyncioTestCase):
    async def test_served_entrypoint_and_dependencies_share_revision(self) -> None:
        from dashboard.backend.app import dashboard_assets, serve_index
        response = await serve_index()
        self.assertIn(f'/static/js/main.js?v={dashboard_assets.revision}', response.body.decode())
        scope = {"type": "http", "method": "GET", "path": "/js/main.js", "headers": []}
        module = await dashboard_assets.get_response("js/main.js", scope)
        self.assertIn(f'./components/control_bar.js?v={dashboard_assets.revision}', module.body.decode())
        self.assertIn(f'./components/charts.js?v={dashboard_assets.revision}', module.body.decode())

    async def test_all_imports_share_content_revision_and_ignore_old_etag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "main.js"
            file.write_text('import { state } from "./state.js";\nimport "./components/chart.js";\n', encoding="utf-8")
            assets = DashboardAssets(directory)
            scope = {"type": "http", "method": "GET", "path": "/main.js", "headers": [(b"if-none-match", b"old")]}
            response = await assets.get_response("main.js", scope)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(response.body.decode().count(f"?v={assets.revision}"), 2)
            file.write_text('import "./new.js";', encoding="utf-8")
            self.assertNotEqual(DashboardAssets(directory).revision, assets.revision)
