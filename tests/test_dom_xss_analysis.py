import pytest
import requests
from tools.xss_tools import _test_dom_target, execute_xss_test, _xss_result


class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP Error {self.status_code}")


def test_dom_analysis_source_and_sink_potential_with_evidence(monkeypatch):
    """1. A JavaScript asset containing a source and a sink -> potential
    (unverified) finding, with evidence, but never confirmed by static analysis."""
    sample_js = """
    function displaySearch() {
        var query = new URLSearchParams(location.search).get('q');
        document.getElementById('result').innerHTML = query;
    }
    """

    def mock_get(url, timeout=5):
        return MockResponse(sample_js)

    monkeypatch.setattr("requests.get", mock_get)

    state = {"target_url": "http://localhost:3000"}
    target = {"url": "http://localhost:3000/assets/search.js", "xss_target_type": "dom"}

    result = _test_dom_target(state, target)

    assert result["finding_type"] == "xss"
    # Detection-only: reported as a potential/unverified lead, not confirmed.
    assert result["data"]["test_status"] == "potential"
    assert result["data"]["suspected"] is True
    assert result["data"]["confirmed"] is False
    assert result["data"]["vulnerable"] is False

    evidence = result["data"].get("evidence")
    assert isinstance(evidence, dict)
    assert evidence["asset_url"] == "http://localhost:3000/assets/search.js"
    assert "location property" in evidence["sources"] or "URLSearchParams" in evidence["sources"]
    assert "innerHTML/outerHTML assignment" in evidence["sinks"]
    assert evidence["validation_status"] == "unverified_static_lead"
    assert "snippet" in evidence


def test_dom_analysis_no_patterns_negative(monkeypatch):
    """2. A JavaScript asset with no matching patterns -> static scan completed, not vulnerability-confirmed."""
    sample_js = """
    console.log("Analytics initialized");
    function calculateSum(a, b) {
        return a + b;
    }
    """

    def mock_get(url, timeout=5):
        return MockResponse(sample_js)

    monkeypatch.setattr("requests.get", mock_get)

    state = {"target_url": "http://localhost:3000"}
    target = {"url": "http://localhost:3000/assets/math.js", "xss_target_type": "dom"}

    result = _test_dom_target(state, target)

    assert result["finding_type"] == "xss"
    assert result["data"]["test_status"] == "negative"
    assert result["data"]["confirmed"] is False
    assert result["data"]["vulnerable"] is False
    assert "no actionable source-sink flow" in result["data"]["detail"]


def test_dom_analysis_missing_url_inconclusive():
    """3. A missing asset URL -> inconclusive."""
    state = {"target_url": "http://localhost:3000"}
    target = {"xss_target_type": "dom"}

    result = _test_dom_target(state, target)

    assert result["data"]["test_status"] == "inconclusive"
    assert "JavaScript asset URL is missing" in result["data"]["detail"]


def test_dom_analysis_outside_origin_skipped():
    """4. An asset outside the configured origin -> skipped."""
    state = {"target_url": "http://localhost:3000"}
    target = {"url": "https://external-cdn.com/tracking.js", "xss_target_type": "dom"}

    result = _test_dom_target(state, target)

    assert result["data"]["test_status"] == "skipped"
    assert "outside the configured target origin" in result["data"]["detail"]


def test_dom_analysis_retrieval_failure_inconclusive(monkeypatch):
    """5. A retrieval failure -> inconclusive."""
    def mock_get(url, timeout=5):
        raise requests.ConnectionError("Connection refused by target")

    monkeypatch.setattr("requests.get", mock_get)

    state = {"target_url": "http://localhost:3000"}
    target = {"url": "http://localhost:3000/assets/missing.js", "xss_target_type": "dom"}

    result = _test_dom_target(state, target)

    assert result["data"]["test_status"] == "inconclusive"
    assert "Could not retrieve JavaScript asset" in result["data"]["detail"]


def test_execute_xss_test_routes_static_js_to_dom_handler(monkeypatch):
    """Verify execute_xss_test automatically assigns xss_target_type='dom' to static JS assets and routes."""
    def mock_get(url, timeout=5):
        return MockResponse("console.log('clean vendor script');")

    monkeypatch.setattr("requests.get", mock_get)

    state = {"target_url": "http://localhost:3000"}
    target = {"url": "http://localhost:3000/main.js"}  # Note: no xss_target_type initially

    result = execute_xss_test(state, target)

    assert target["xss_target_type"] == "dom"
    assert result["data"]["test_status"] == "negative"
