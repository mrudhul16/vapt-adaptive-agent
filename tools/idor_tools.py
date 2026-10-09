from urllib.parse import urljoin, urlparse

import base64
import json

from playwright.sync_api import sync_playwright


def is_local_target(url, base_url):

    try:

        target = urlparse(url)

        base = urlparse(base_url)

        return (
            target.hostname in {
                "localhost",
                "127.0.0.1"
            }

            and target.port == base.port
        )

    except Exception:

        return False


def _get_token(authenticated_session):

    if not authenticated_session:
        return None

    token = authenticated_session.get(
        "token"
    )

    if token:
        return token

    token = authenticated_session.get(
        "auth_token"
    )

    if token:
        return token

    return None


def _decode_jwt_payload(token):

    if not token:
        return None

    try:

        parts = token.split(".")

        if len(parts) != 3:
            return None

        payload = parts[1]

        padding = "=" * (
            4 - len(payload) % 4
        )

        decoded = base64.urlsafe_b64decode(
            payload + padding
        )

        return json.loads(
            decoded.decode("utf-8")
        )

    except Exception:

        return None


def _get_authenticated_user_id(
    authenticated_session
):

    if not authenticated_session:
        return None

    # Preferred: Use explicitly stored user ID from a trusted authentication flow
    explicit_user_id = authenticated_session.get("user_id")
    if explicit_user_id is not None:
        return explicit_user_id

    # Fallback: Extract from the token payload.
    # WARNING: Decoding a JWT locally does not verify its cryptographic signature.
    # This is only safe here because the token is obtained directly from a trusted
    # session established by our authentication flow, not from an unverified source.
    token = _get_token(
        authenticated_session
    )

    payload = _decode_jwt_payload(
        token
    )

    if not payload:
        return None

    for key in (
        "id",
        "userId",
        "user_id",
        "sub"
    ):

        if payload.get(key) is not None:

            return payload.get(key)

    data = payload.get(
        "data"
    )

    if isinstance(
        data,
        dict
    ):

        for key in (
            "id",
            "userId",
            "user_id"
        ):

            if data.get(key) is not None:

                return data.get(key)

    return None


def _get_headers(
    authenticated_session
):

    token = _get_token(
        authenticated_session
    )

    if not token:
        return {}

    return {
        "Authorization": f"Bearer {token}"
    }


def discover_idor_targets(state):

    target_url = state[
        "target_url"
    ]

    targets = []

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context()

        page = context.new_page()

        try:

            page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=15000
            )

            page.wait_for_timeout(700)

            basket_collection = {

                "type": "basket_collection",

                "url": urljoin(
                    target_url,
                    "/rest/basket"
                ),

                "method": "GET"
            }

            if is_local_target(
                basket_collection["url"],
                target_url
            ):

                targets.append(
                    basket_collection
                )

            for basket_id in range(1, 6):

                target = {

                    "type": "basket_object",

                    "url": urljoin(
                        target_url,
                        f"/rest/basket/{basket_id}"
                    ),

                    "method": "GET",

                    "object_id": basket_id
                }

                if is_local_target(
                    target["url"],
                    target_url
                ):

                    targets.append(
                        target
                    )

        finally:

            browser.close()

    return targets


def _request(
    context,
    url,
    authenticated_session
):

    headers = _get_headers(
        authenticated_session
    )

    return context.request.get(
        url,
        headers=headers,
        timeout=10000
    )


def execute_idor_test(
    state,
    target
):

    target_url = state[
        "target_url"
    ]

    authenticated_session = (
        state[
            "idor_state"
        ].get(
            "authenticated_session",
            {}
        )
    )

    if not is_local_target(
        target.get("url", ""),
        target_url
    ):

        return {
            "success": False,

            "data": {
                "vulnerable": False,

                "error": (
                    "Non-local target rejected."
                )
            }
        }

    token = _get_token(
        authenticated_session
    )

    authenticated_user_id = (
        _get_authenticated_user_id(
            authenticated_session
        )
    )

    result = {
        "target": target,

        "vulnerable": False,
        "suspected": False,

        "status_code": None,

        "response": None,

        "unauthorized_access": False,

        "authenticated_request": bool(
            token
        ),

        "authenticated_user_id": (
            authenticated_user_id
        ),

        "resource_owner_id": None,

        "ownership_mismatch": False,

        "error": None
    }

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context()

        try:

            response = _request(
                context,
                target["url"],
                authenticated_session
            )

            result[
                "status_code"
            ] = response.status

            try:

                body = response.json()

            except Exception:

                body = response.text()

            if isinstance(
                body,
                dict
            ):

                resource_data = body.get(
                    "data",
                    body
                )

                if isinstance(
                    resource_data,
                    dict
                ):

                    resource_owner_id = (
                        resource_data.get(
                            "UserId"
                        )
                    )

                    if resource_owner_id is None:

                        resource_owner_id = (
                            resource_data.get(
                                "userId"
                            )
                        )

                    if resource_owner_id is None:

                        resource_owner_id = (
                            resource_data.get(
                                "user_id"
                            )
                        )

                    result[
                        "resource_owner_id"
                    ] = resource_owner_id

            if (
                response.status == 200

                and authenticated_user_id
                is not None

                and result[
                    "resource_owner_id"
                ] is not None
            ):

                ownership_mismatch = (

                    str(
                        authenticated_user_id
                    )

                    != str(
                        result[
                            "resource_owner_id"
                        ]
                    )
                )

                result[
                    "ownership_mismatch"
                ] = ownership_mismatch

                if ownership_mismatch:
                    result[
                        "unauthorized_access"
                    ] = True

                    result[
                        "suspected"
                    ] = True
                    
                    # Do not independently confirm without secondary verification
                    result[
                        "vulnerable"
                    ] = True

        except Exception as exc:

            result[
                "error"
            ] = str(exc)

        finally:

            browser.close()

    return {
        "success": True,

        "data": result
    }


def discover_basket_ids(state):

    target_url = state[
        "target_url"
    ]

    authenticated_session = (
        state[
            "idor_state"
        ].get(
            "authenticated_session",
            {}
        )
    )

    discovered = []

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context()

        try:

            response = _request(
                context,

                urljoin(
                    target_url,
                    "/rest/basket"
                ),

                authenticated_session
            )

            if response.status != 200:
                return discovered

            try:

                data = response.json()

            except Exception:

                return discovered

            if isinstance(
                data,
                dict
            ):

                baskets = data.get(
                    "data",
                    []
                )

            elif isinstance(
                data,
                list
            ):

                baskets = data

            else:

                baskets = []

            for basket in baskets:

                if not isinstance(
                    basket,
                    dict
                ):

                    continue

                basket_id = basket.get(
                    "id"
                )

                if basket_id is None:
                    continue

                discovered.append({

                    "type": "basket_object",

                    "url": urljoin(
                        target_url,
                        f"/rest/basket/{basket_id}"
                    ),

                    "method": "GET",

                    "object_id": basket_id,

                    "source": "basket_collection"
                })

        except Exception:

            pass

        finally:

            browser.close()

    return discovered