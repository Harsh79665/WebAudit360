"""WebAudit 360 — Chrome Extension Boilerplate Verification Tests
Author: Harsh Patel
"""

import json
import os


def test_extension_manifest_v3_validity():
    manifest_path = os.path.join("extension", "manifest.json")
    assert os.path.exists(manifest_path), "manifest.json must exist in extension/"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Manifest V3 Requirements
    assert manifest["manifest_version"] == 3
    assert "name" in manifest
    assert "version" in manifest
    assert "action" in manifest
    assert manifest["action"]["default_popup"] == "popup.html"
    assert "permissions" in manifest
    assert "activeTab" in manifest["permissions"]
    assert "storage" in manifest["permissions"]
    assert "background" in manifest
    assert manifest["background"]["service_worker"] == "background.js"


def test_extension_assets_exist_and_non_empty():
    required_files = [
        "manifest.json",
        "popup.html",
        "popup.css",
        "popup.js",
        "background.js",
        "README.md"
    ]

    for fname in required_files:
        fpath = os.path.join("extension", fname)
        assert os.path.exists(fpath), f"{fname} must exist"
        assert os.path.getsize(fpath) > 50, f"{fname} must not be empty"


def test_popup_html_contains_required_controls():
    popup_path = os.path.join("extension", "popup.html")
    with open(popup_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "btn-start-audit" in content
    assert "active-url-display" in content
    assert "results-container" in content
    assert "popup.js" in content
