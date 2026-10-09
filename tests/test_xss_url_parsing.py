import pytest
from agents.xss_agent import _expand_xss_targets, _target_identity
from tools.xss_tools import _test_url_value

def test_expand_xss_targets_input():
    target = {"url": "http://localhost:3000/#/contact", "type": "input", "index": 0}
    expanded = _expand_xss_targets(target)
    assert len(expanded) == 1
    assert expanded[0]["xss_target_type"] == "input"

def test_expand_xss_targets_url_parameter():
    target = {"url": "http://localhost:3000/search?q=apple", "type": "endpoint"}
    expanded = _expand_xss_targets(target)
    assert len(expanded) == 1
    assert expanded[0]["xss_target_type"] == "url_parameter"
    assert expanded[0]["parameter"] == "q"

def test_expand_xss_targets_fragment_parameter():
    target = {"url": "http://localhost:3000/#/search?q=apple&sort=asc", "type": "endpoint"}
    expanded = _expand_xss_targets(target)
    assert len(expanded) == 2
    types = [t["xss_target_type"] for t in expanded]
    params = [t["parameter"] for t in expanded]
    assert all(t == "fragment" for t in types)
    assert set(params) == {"q", "sort"}

def test_expand_xss_targets_mixed():
    target = {"url": "http://localhost:3000/api?id=1#/search?q=apple", "type": "input", "index": 0}
    expanded = _expand_xss_targets(target)
    # Expecting 3 targets: 1 input, 1 url_parameter (id), 1 fragment (q)
    assert len(expanded) == 3
    types = {t["xss_target_type"]: t.get("parameter") for t in expanded}
    assert "input" in types
    assert types["url_parameter"] == "id"
    assert types["fragment"] == "q"

def test_target_identity_separation():
    t1 = {"url": "http://localhost:3000/#/search?q=apple", "xss_target_type": "input", "parameter": "q"}
    t2 = {"url": "http://localhost:3000/#/search?q=apple", "xss_target_type": "fragment", "parameter": "q"}
    assert _target_identity(t1) != _target_identity(t2)

def test_expand_xss_targets_empty_query_param():
    target = {"url": "http://localhost:3000/rest/products/search?q=", "type": "endpoint"}
    expanded = _expand_xss_targets(target)
    assert len(expanded) == 1
    assert expanded[0]["xss_target_type"] == "url_parameter"
    assert expanded[0]["parameter"] == "q"

def test_expand_xss_targets_empty_fragment_param():
    target = {"url": "http://localhost:3000/#/search?q=", "type": "endpoint"}
    expanded = _expand_xss_targets(target)
    assert len(expanded) == 1
    assert expanded[0]["xss_target_type"] == "fragment"
    assert expanded[0]["parameter"] == "q"

def test_expand_xss_targets_plain_api_endpoint():
    target = {"url": "http://localhost:3000/api/Users", "type": "endpoint", "method": "GET"}
    expanded = _expand_xss_targets(target)
    # Plain API endpoint without parameters or input metadata should produce no browser-input candidates
    assert len(expanded) == 0

def test_expand_xss_targets_plain_rest_endpoint():
    target = {"url": "http://localhost:3000/rest/user/login", "type": "endpoint", "method": "POST"}
    expanded = _expand_xss_targets(target)
    assert len(expanded) == 0

def test_expand_xss_targets_static_assets():
    js_target = {"url": "http://localhost:3000/main.js", "type": "asset"}
    css_target = {"url": "http://localhost:3000/styles.css", "type": "asset"}
    png_target = {"url": "http://localhost:3000/assets/logo.png", "type": "asset"}
    assert _expand_xss_targets(js_target) == []
    assert _expand_xss_targets(css_target) == []
    assert _expand_xss_targets(png_target) == []

def test_expand_xss_targets_dom_and_stored():
    dom_target = {"url": "http://localhost:3000/#/score-board", "dom_sink": "innerHTML"}
    stored_target = {"url": "http://localhost:3000/rest/products/1/reviews", "type": "stored"}
    
    dom_expanded = _expand_xss_targets(dom_target)
    assert len(dom_expanded) == 1
    assert dom_expanded[0]["xss_target_type"] == "dom"

    stored_expanded = _expand_xss_targets(stored_target)
    assert len(stored_expanded) == 1
    assert stored_expanded[0]["xss_target_type"] == "stored"

