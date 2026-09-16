"""Route + panel-HTML contract tests.

Legacy routes remain part of the public surface. Feature additions may append
new routes and panel sections, but must not remove the existing contract.
"""
import json
import os

from fastapi.testclient import TestClient

import backend.main as main

_BASELINE = os.path.join(os.path.dirname(__file__), "baseline")


def test_legacy_route_surface_is_preserved_and_original_image_api_is_added():
    spec = main.app.openapi()
    current = {
        f"{m.upper()} {p}"
        for p, item in spec["paths"].items()
        for m in item.keys()
    }
    expected = set(
        json.load(open(os.path.join(_BASELINE, "routes.json"), encoding="utf-8"))
    )
    assert expected <= current
    assert {
        "GET /panel/api/media/originals/status",
        "GET /panel/api/media/originals/pending",
        "POST /panel/api/media/originals/recover",
        "POST /panel/api/media/originals/cancel",
    } <= current


def test_panel_preserves_legacy_shell_and_adds_original_image_recovery():
    client = TestClient(main.app)
    response = client.get("/panel")
    body = response.text

    assert response.status_code == 200
    assert "charset=utf-8" in response.headers["content-type"].lower()

    # Stable legacy shell markers.
    assert 'id="mainContainer"' in body
    assert 'id="page-scrape"' in body
    assert 'id="backfillBtn"' in body
    assert 'id="videoBackfillBtn"' in body
    assert 'id="page-export"' in body

    # New original-image recovery panel and controller.
    assert 'id="originalImageRecoverySection"' in body
    assert 'id="originalImageRecoverBtn"' in body
    assert "/panel/api/media/originals/recover" in body
    assert "startOriginalImageRecovery" in body
