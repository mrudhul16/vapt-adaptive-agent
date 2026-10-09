import pytest
from agents.xss_agent import (
    classify_unexpandable_targets,
    _is_static_js_target,
    _is_non_script_static_target,
    _has_identifiable_inputs,
)


def _build_test_state(targets):
    return {
        "target_url": "http://localhost:3000",
        "xss_state": {
            "discovered_targets": list(targets),
            "tested_targets": [],
            "skipped_targets": [],
            "remaining_targets": list(targets),
            "successful_targets": [],
            "confirmed_vulnerabilities": [],
            "inconclusive_targets": [],
            "unclassified_targets": [],
            "observations": [],
            "completed": False,
        }
    }


def test_valid_candidates_not_removed_from_queue():
    """Verify no valid XSS candidate is removed from the queue or marked unclassified."""
    valid_input = {
        "url": "http://localhost:3000/#/contact",
        "type": "input",
        "index": 0,
        "selector": "#feedback"
    }
    valid_query = {
        "url": "http://localhost:3000/search?q=apple",
        "type": "endpoint"
    }
    valid_fragment = {
        "url": "http://localhost:3000/#/search?q=",
        "type": "endpoint"
    }
    valid_api_param = {
        "url": "http://localhost:3000/api/users",
        "type": "endpoint",
        "parameter": "username"
    }
    valid_stored = {
        "url": "http://localhost:3000/rest/products/1/reviews",
        "type": "stored",
        "xss_target_type": "stored"
    }

    state = _build_test_state([
        valid_input,
        valid_query,
        valid_fragment,
        valid_api_param,
        valid_stored
    ])

    classify_unexpandable_targets(state)
    xss_state = state["xss_state"]

    # None of these should be classified as unclassified or skipped
    assert len(xss_state["unclassified_targets"]) == 0
    assert len(xss_state["skipped_targets"]) == 0
    assert len(xss_state["tested_targets"]) == 0
    # All must remain in the queue
    assert len(xss_state["remaining_targets"]) == 5


def test_static_assets_not_counted_as_tested_without_analysis():
    """Verify static assets are not counted as tested without analysis."""
    js_target = {"url": "http://localhost:3000/main.js", "type": "asset"}
    js_chunk = {"url": "http://localhost:3000/runtime.mjs", "category": "js_assets"}
    css_target = {"url": "http://localhost:3000/styles.css", "type": "asset"}
    png_target = {"url": "http://localhost:3000/assets/logo.png", "type": "asset"}

    state = _build_test_state([js_target, js_chunk, css_target, png_target])

    classify_unexpandable_targets(state)
    xss_state = state["xss_state"]

    # CRITICAL: Static assets must NEVER be counted as tested
    assert len(xss_state["tested_targets"]) == 0

    # JavaScript assets requiring DOM source/sink analysis must be unclassified
    unclassified_urls = [u["target"]["url"] for u in xss_state["unclassified_targets"]]
    assert "http://localhost:3000/main.js" in unclassified_urls
    assert "http://localhost:3000/runtime.mjs" in unclassified_urls

    # Details must indicate source/sink analysis requirement
    for record in xss_state["unclassified_targets"]:
        assert record["status"] == "unclassified"
        assert "source/sink" in record["detail"]

    # Non-script static assets (CSS, PNG) should be recorded as skipped
    skipped_urls = [s["url"] for s in xss_state["skipped_targets"]]
    assert "http://localhost:3000/styles.css" in skipped_urls
    assert "http://localhost:3000/assets/logo.png" in skipped_urls


def test_unclassified_targets_recorded_only_once():
    """Verify unclassified targets are recorded only once across multiple invocations."""
    js_target = {"url": "http://localhost:3000/main.js", "type": "asset"}
    unresolved_api = {"url": "http://localhost:3000/api/version", "type": "endpoint", "method": "GET"}

    state = _build_test_state([js_target, unresolved_api])

    # First run
    classify_unexpandable_targets(state)
    assert len(state["xss_state"]["unclassified_targets"]) == 2

    # Second run (simulating idempotent calls or loop steps)
    classify_unexpandable_targets(state)
    assert len(state["xss_state"]["unclassified_targets"]) == 2

    # Third run
    classify_unexpandable_targets(state)
    assert len(state["xss_state"]["unclassified_targets"]) == 2


def test_separate_report_counts():
    """Verify separate counts for tested, skipped, confirmed, suspected, and unclassified."""
    tested_target = {"url": "http://localhost:3000/api/tested", "xss_target_type": "input"}
    skipped_static = {"url": "http://localhost:3000/styles.css", "type": "asset"}
    confirmed_target = {"url": "http://localhost:3000/#/search?q=", "xss_target_type": "fragment", "parameter": "q"}
    suspected_target = {"url": "http://localhost:3000/rest/products/1/reviews", "xss_target_type": "stored"}
    js_target = {"url": "http://localhost:3000/main.js", "type": "asset"}
    unresolved_api = {"url": "http://localhost:3000/api/version", "type": "endpoint", "method": "GET"}

    state = _build_test_state([
        tested_target,
        skipped_static,
        confirmed_target,
        suspected_target,
        js_target,
        unresolved_api
    ])

    xss_state = state["xss_state"]
    # Simulate prior execution outcomes
    xss_state["tested_targets"] = [tested_target, confirmed_target, suspected_target]
    xss_state["confirmed_vulnerabilities"] = [confirmed_target]
    xss_state["successful_targets"] = [suspected_target]

    classify_unexpandable_targets(state)

    tested_count = len(xss_state["tested_targets"])
    skipped_count = len(xss_state["skipped_targets"])
    confirmed_count = len(xss_state["confirmed_vulnerabilities"])
    suspected_count = len(xss_state["successful_targets"])
    unclassified_count = len(xss_state["unclassified_targets"])

    assert tested_count == 3
    assert skipped_count == 1
    assert confirmed_count == 1
    assert suspected_count == 1
    assert unclassified_count == 2


def test_workflow_does_not_claim_full_coverage_while_unclassified_remain():
    """Verify workflow does not claim full coverage while unclassified targets remain."""
    js_target = {"url": "http://localhost:3000/main.js", "type": "asset"}
    tested_target = {"url": "http://localhost:3000/search?q=1", "parameter": "q"}

    state = _build_test_state([js_target, tested_target])
    xss_state = state["xss_state"]
    xss_state["tested_targets"] = [tested_target]

    classify_unexpandable_targets(state)

    discovered = xss_state["discovered_targets"]
    tested = xss_state["tested_targets"]
    skipped = xss_state["skipped_targets"]

    remaining = [
        target
        for target in discovered
        if target not in tested and target not in skipped
    ]

    # Unclassified targets must remain in `remaining`
    assert len(remaining) == 1
    assert remaining[0]["url"] == "http://localhost:3000/main.js"

    # Coverage cannot claim completed while remaining / unclassified targets exist
    completed = (
        len(xss_state["remaining_targets"]) == 0
        and len(xss_state["unclassified_targets"]) == 0
    )
    assert completed is False


def test_run_xss_specialist_integration_finish(monkeypatch):
    """Verify run_xss_specialist integration with action == finish, classification, and report metrics."""
    from agent import run_xss_specialist

    # Mock choose_next_target to simulate finish
    def mock_choose(s):
        return {"action": "finish", "target_index": None, "reason": "No candidates left"}

    monkeypatch.setattr("agent.choose_next_target", mock_choose)
    # Mock browser discovery in get_xss_targets to avoid launching Playwright in unit tests
    monkeypatch.setattr("tools.xss_tools.get_xss_targets", lambda s: [])

    state = {
        "target_url": "http://localhost:3000",
        "findings": [],
        "metrics": {"modules_executed": 0, "findings_discovered": 0, "chains_triggered": 0, "chains_completed": 0, "workflow_steps": 0},
    }

    recon_result = {
        "data": {
            "attack_surface": {
                "js_assets": [{"url": "http://localhost:3000/main.js"}],
                "page_endpoints": [
                    {"url": "http://localhost:3000/assets/logo.png"},
                    {"url": "http://localhost:3000/api/version", "type": "endpoint", "method": "GET"}
                ]
            }
        }
    }

    result = run_xss_specialist(state, recon_result)

    assert result["specialist"] == "xss"
    assert result["completed"] is False
    assert result["tested_count"] == 0
    assert result["skipped_count"] >= 1  # logo.png skipped
    assert result["unclassified_count"] >= 2  # main.js and api/version unclassified
    assert len(result["unclassified_targets"]) == result["unclassified_count"]
    # Verify report fields are present and separated
    assert "tested_count" in result
    assert "skipped_count" in result
    assert "confirmed_count" in result
    assert "successful_count" in result
    assert "unclassified_count" in result

