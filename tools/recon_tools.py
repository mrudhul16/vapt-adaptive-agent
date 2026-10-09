import re

from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


REQUEST_TIMEOUT = 10

VALID_PARAMETER_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]{2,}$"
)

VALID_PATH_PATTERN = re.compile(
    r"^/[A-Za-z0-9_./?=&:%@+~\\-]+$"
)


def is_local_target(url, base_url):
    try:
        target = urlparse(url)
        base = urlparse(base_url)

        return (
            target.scheme in {"http", "https"}
            and target.hostname in {"localhost", "127.0.0.1"}
            and target.port == base.port
        )

    except Exception:
        return False


def is_valid_endpoint(url, base_url):
    if not is_local_target(url, base_url):
        return False

    parsed = urlparse(url)
    path = parsed.path

    if path in {"", "/"}:
        return True

    if not VALID_PATH_PATTERN.match(path):
        return False

    segments = [
        segment
        for segment in path.split("/")
        if segment
    ]

    if not segments:
        return True

    garbage_segments = {
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        ",",
        ";",
        ":",
    }

    if any(
        segment in garbage_segments
        for segment in segments
    ):
        return False

    if (
        len(segments) == 1
        and segments[0].isdigit()
    ):
        return False

    if (
        len(path) == 2
        and path[1].isalpha()
    ):
        return False

    return True


def is_valid_parameter(parameter):
    if not isinstance(parameter, str):
        return False

    parameter = parameter.strip()

    if not parameter:
        return False

    return bool(
        VALID_PARAMETER_PATTERN.match(parameter)
    )


def clean_parameters(parameters):
    cleaned = []

    for parameter in parameters:
        if not is_valid_parameter(parameter):
            continue

        if parameter not in cleaned:
            cleaned.append(parameter)

    return sorted(cleaned)


def clean_endpoints(endpoints, base_url):
    cleaned = []

    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue

        endpoint = endpoint.strip()

        if not endpoint:
            continue

        if not is_valid_endpoint(
            endpoint,
            base_url,
        ):
            continue

        if endpoint not in cleaned:
            cleaned.append(endpoint)

    return sorted(cleaned)


def fetch_page(url):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/154.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,*/*;q=0.8"
        ),
        "Connection": "close",
    }

    last_error = None

    for _ in range(3):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            return response

        except requests.RequestException as exc:
            last_error = exc

    if last_error:
        raise last_error

    raise RuntimeError("Request failed.")


def discover_recon_targets(state):
    target_url = state["target_url"]

    targets = []

    response = fetch_page(target_url)

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    targets.append(
        {
            "type": "technology",
            "url": target_url,
        }
    )

    targets.append(
        {
            "type": "headers",
            "url": target_url,
        }
    )

    targets.append(
        {
            "type": "html",
            "url": target_url,
        }
    )

    discovered_urls = set()

    for tag in soup.find_all(
        [
            "a",
            "script",
            "link",
            "form",
        ]
    ):
        value = (
            tag.get("href")
            or tag.get("src")
            or tag.get("action")
        )

        if not value:
            continue

        absolute_url = urljoin(
            target_url,
            value,
        )

        if is_valid_endpoint(
            absolute_url,
            target_url,
        ):
            discovered_urls.add(
                absolute_url
            )

    for url in sorted(discovered_urls):
        targets.append(
            {
                "type": "endpoint",
                "url": url,
            }
        )

    for index, form in enumerate(
        soup.find_all("form")
    ):
        action = form.get("action")

        form_url = urljoin(
            target_url,
            action or target_url,
        )

        if is_valid_endpoint(
            form_url,
            target_url,
        ):
            targets.append(
                {
                    "type": "form",
                    "url": form_url,
                    "index": index,
                }
            )

    input_index = 0

    for element in soup.find_all(
        [
            "input",
            "textarea",
            "select",
        ]
    ):
        input_type = element.get(
            "type",
            "text",
        )

        if input_type in {
            "hidden",
            "submit",
            "button",
        }:
            continue

        targets.append(
            {
                "type": "input",
                "url": target_url,
                "index": input_index,
                "input_type": input_type,
                "name": element.get("name"),
                "id": element.get("id"),
            }
        )

        input_index += 1

    return targets


def execute_recon_test(state, target):
    target_url = state["target_url"]

    url = target.get(
        "url",
        target_url,
    )

    if not is_valid_endpoint(
        url,
        target_url,
    ):
        return {
            "success": False,
            "data": {
                "error": (
                    "Invalid or non-local "
                    "reconnaissance target rejected."
                )
            },
        }

    target_type = target.get("type")

    try:
        if target_type == "technology":
            return test_technology(url)

        if target_type == "headers":
            return test_headers(url)

        if target_type == "html":
            return test_html(url)

        if target_type == "endpoint":
            return test_endpoint(
                url,
                target_url,
            )

        if target_type == "form":
            return test_form(
                url,
                target,
            )

        if target_type == "input":
            return test_input(
                url,
                target,
            )

        return {
            "success": False,
            "data": {
                "error": (
                    "Unknown reconnaissance "
                    "target type."
                )
            },
        }

    except Exception as exc:
        return {
            "success": False,
            "data": {
                "error": str(exc),
            },
        }


def test_technology(url):
    response = fetch_page(url)

    headers = response.headers

    technologies = []

    server = headers.get("Server")
    powered_by = headers.get(
        "X-Powered-By"
    )

    if server:
        technologies.append(
            f"Server: {server}"
        )

    if powered_by:
        technologies.append(
            f"X-Powered-By: {powered_by}"
        )

    body = response.text.lower()

    technology_signatures = {
        "Angular": [
            "ng-version",
            "angular",
        ],
        "React": [
            "react",
        ],
        "Vue": [
            "vue",
        ],
        "jQuery": [
            "jquery",
        ],
        "Bootstrap": [
            "bootstrap",
        ],
    }

    for technology, signatures in (
        technology_signatures.items()
    ):
        if any(
            signature in body
            for signature in signatures
        ):
            if technology not in technologies:
                technologies.append(
                    technology
                )

    return {
        "success": True,
        "data": {
            "status_code": response.status_code,
            "technologies": technologies,
        },
    }


def test_headers(url):
    response = fetch_page(url)

    headers = dict(response.headers)

    security_headers = {
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    }

    present = []
    missing = []

    for header in sorted(
        security_headers
    ):
        if header in headers:
            present.append(header)
        else:
            missing.append(header)

    return {
        "success": True,
        "data": {
            "status_code": response.status_code,
            "security_headers": present,
            "missing_security_headers": missing,
        },
    }


def test_html(url):
    response = fetch_page(url)

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    endpoints = set()

    for tag in soup.find_all(
        [
            "a",
            "script",
            "link",
            "form",
        ]
    ):
        value = (
            tag.get("href")
            or tag.get("src")
            or tag.get("action")
        )

        if not value:
            continue

        absolute_url = urljoin(
            url,
            value,
        )

        if is_valid_endpoint(
            absolute_url,
            url,
        ):
            endpoints.add(
                absolute_url
            )

    forms = []

    for form in soup.find_all("form"):
        fields = []

        for element in form.find_all(
            [
                "input",
                "textarea",
                "select",
            ]
        ):
            fields.append(
                {
                    "name": element.get("name"),
                    "id": element.get("id"),
                    "type": element.get(
                        "type",
                        element.name,
                    ),
                }
            )

        forms.append(
            {
                "action": urljoin(
                    url,
                    form.get("action")
                    or url,
                ),
                "method": (
                    form.get(
                        "method",
                        "GET",
                    ).upper()
                ),
                "fields": fields,
            }
        )

    parameters = []

    for element in soup.find_all(
        [
            "input",
            "textarea",
            "select",
        ]
    ):
        name = element.get("name")

        if is_valid_parameter(name):
            parameters.append(name)

    return {
        "success": True,
        "data": {
            "status_code": response.status_code,
            "endpoints": sorted(endpoints),
            "forms": forms,
            "parameters": clean_parameters(
                parameters
            ),
        },
    }


def normalize_js_route(
    value,
    base_url,
):
    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    value = value.strip(
        "\"'` \t\r\n"
    )

    if not value:
        return None

    if value.startswith(
        (
            "http://",
            "https://",
        )
    ):
        absolute_url = value

    elif value.startswith(
        "localhost"
    ):
        absolute_url = (
            "http://" + value
        )

    elif value.startswith(
        "127.0.0.1"
    ):
        absolute_url = (
            "http://" + value
        )

    elif value.startswith("//"):
        # Protocol-relative URL
        absolute_url = "https:" + value

    elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)", value) and "localhost" not in value:
        # Looks like a domain (e.g., api.ipify.org or accounts.google.com)
        absolute_url = "https://" + value

    elif value.startswith("/"):
        absolute_url = urljoin(
            base_url,
            value,
        )

    else:
        absolute_url = urljoin(
            base_url,
            "/" + value,
        )

    if is_valid_endpoint(
        absolute_url,
        base_url,
    ):
        return absolute_url

    return None


def extract_js_endpoints(
    body,
    base_url,
):
    endpoints = set()

    important_prefixes = (
        "/api/",
        "/rest/",
        "/graphql",
        "/auth",
        "/authentication",
        "/login",
        "/logout",
        "/register",
        "/user",
        "/users",
        "/admin",
        "/basket",
        "/baskets",
        "/order",
        "/orders",
        "/payment",
        "/payments",
        "/address",
        "/addresses",
        "/account",
        "/profile",
        "/delivery",
        "/card",
        "/cards",
        "/wallet",
        "/search",
        "/feedback",
        "/contact",
        "/complaint",
        "/comment",
        "/message",
        "/quantity",
        "/checkout",
    )

    quoted_pattern = re.compile(
        r"""["'`]([^"'`<>\r\n]{2,})["'`]""",
        re.IGNORECASE,
    )

    for match in quoted_pattern.finditer(body):
        value = match.group(1).strip()

        if not value:
            continue

        if not (
            value.startswith("/")
            or value.startswith("http://")
            or value.startswith("https://")
            or value.startswith("localhost")
            or value.startswith("127.0.0.1")
        ):
            continue

        absolute_url = normalize_js_route(
            value,
            base_url,
        )

        if not absolute_url:
            continue

        parsed = urlparse(
            absolute_url
        )

        path = parsed.path.lower()

        if path.startswith(
            important_prefixes
        ):
            endpoints.add(
                absolute_url
            )

    route_pattern = re.compile(
        r"""(?<![A-Za-z0-9_])(/(?:api|rest|graphql|auth|authentication|login|logout|register|user|users|admin|basket|baskets|order|orders|payment|payments|address|addresses|account|profile|delivery|card|cards|wallet|search|feedback|contact|complaint|comment|message|quantity|checkout)(?:[A-Za-z0-9_./?=&:%@+~#\-\[\]]*)?)""",
        re.IGNORECASE,
    )

    for match in route_pattern.finditer(body):
        value = match.group(1)

        absolute_url = normalize_js_route(
            value,
            base_url,
        )

        if absolute_url:
            endpoints.add(
                absolute_url
            )

    return endpoints


def extract_general_js_routes(
    body,
    base_url,
):
    endpoints = set()

    patterns = [
        re.compile(
            r"""["'`](/[^"'`<>\s\\]{2,})["'`]""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""["'`](https?://[^"'`<>\s\\]+)["'`]""",
            re.IGNORECASE,
        ),
    ]

    important_keywords = (
        "/api/",
        "/rest/",
        "/graphql",
        "/auth",
        "/login",
        "/logout",
        "/register",
        "/user",
        "/users",
        "/admin",
        "/basket",
        "/order",
        "/payment",
        "/address",
        "/account",
        "/profile",
        "/delivery",
        "/wallet",
        "/search",
        "/feedback",
        "/contact",
        "/quantity",
        "/checkout",
    )

    for pattern in patterns:
        matches = pattern.findall(body)

        for value in matches:
            absolute_url = normalize_js_route(
                value,
                base_url,
            )

            if not absolute_url:
                continue

            parsed = urlparse(
                absolute_url
            )

            path = parsed.path.lower()

            if any(
                keyword in path
                for keyword in important_keywords
            ):
                endpoints.add(
                    absolute_url
                )

    return endpoints


def extract_js_parameters(body):
    parameters = set()

    patterns = [
        r"""[?&]([A-Za-z_][A-Za-z0-9_-]{2,})=""",

        r"""[?&]\$\{?([A-Za-z_][A-Za-z0-9_-]{2,})\}?=""",

        r"""[?&]\$\{?([A-Za-z_][A-Za-z0-9_-]{2,})\}?&""",
    ]

    for pattern in patterns:
        matches = re.findall(
            pattern,
            body,
            flags=re.IGNORECASE,
        )

        for parameter in matches:
            if is_valid_parameter(
                parameter
            ):
                parameters.add(
                    parameter
                )

    return parameters


def extract_interesting_strings(body):
    keywords = [
        "api",
        "graphql",
        "rest",
        "admin",
        "login",
        "logout",
        "register",
        "authentication",
        "authorization",
        "auth",
        "token",
        "session",
        "user",
        "users",
        "basket",
        "order",
        "payment",
        "address",
        "profile",
        "account",
        "delivery",
        "wallet",
        "search",
        "feedback",
        "contact",
        "quantity",
        "checkout",
    ]

    body_lower = body.lower()

    found = []

    for keyword in keywords:
        if keyword in body_lower:
            found.append(keyword)

    return sorted(set(found))


def test_endpoint(
    url,
    base_url=None,
):
    if base_url is None:
        base_url = url

    response = fetch_page(url)

    content_type = response.headers.get(
        "Content-Type",
        "",
    )

    body = response.text

    endpoints = set()
    parameters = set()
    interesting_strings = []

    is_javascript = (
        ".js" in urlparse(
            url
        ).path.lower()
        or "javascript"
        in content_type.lower()
    )

    if is_javascript:
        endpoints.update(
            extract_js_endpoints(
                body,
                base_url,
            )
        )

        endpoints.update(
            extract_general_js_routes(
                body,
                base_url,
            )
        )

        parameters.update(
            extract_js_parameters(
                body
            )
        )

        interesting_strings.extend(
            extract_interesting_strings(
                body
            )
        )

    else:
        url_patterns = re.findall(
            r"""["'`](https?://[^"'`<>\s\\]+|/[^"'`<>\s\\]+)["'`]""",
            body,
            flags=re.IGNORECASE,
        )

        for value in url_patterns:
            absolute_url = urljoin(
                url,
                value,
            )

            if is_valid_endpoint(
                absolute_url,
                base_url,
            ):
                endpoints.add(
                    absolute_url
                )

        parameter_patterns = re.findall(
            r"""[?&]([A-Za-z_][A-Za-z0-9_-]{2,})=""",
            body,
        )

        for parameter in parameter_patterns:
            if is_valid_parameter(
                parameter
            ):
                parameters.add(
                    parameter
                )

        interesting_strings.extend(
            extract_interesting_strings(
                body
            )
        )

    return {
        "success": True,
        "data": {
            "status_code": response.status_code,
            "endpoint": url,
            "content_type": content_type,
            "endpoints": clean_endpoints(
                endpoints,
                base_url,
            ),
            "parameters": clean_parameters(
                parameters
            ),
            "interesting_strings": sorted(
                set(interesting_strings)
            ),
        },
    }


def test_form(
    url,
    target,
):
    response = fetch_page(url)

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    forms = soup.find_all("form")

    index = target.get(
        "index",
        0,
    )

    if index >= len(forms):
        return {
            "success": False,
            "data": {
                "error": "Form not found.",
            },
        }

    form = forms[index]

    fields = []

    for element in form.find_all(
        [
            "input",
            "textarea",
            "select",
        ]
    ):
        fields.append(
            {
                "name": element.get("name"),
                "id": element.get("id"),
                "type": element.get(
                    "type",
                    element.name,
                ),
            }
        )

    action = urljoin(
        url,
        form.get("action")
        or url,
    )

    parameters = clean_parameters(
        [
            field.get("name")
            for field in fields
            if field.get("name")
        ]
    )

    return {
        "success": True,
        "data": {
            "form_action": action,
            "method": (
                form.get(
                    "method",
                    "GET",
                ).upper()
            ),
            "forms": [
                {
                    "action": action,
                    "method": (
                        form.get(
                            "method",
                            "GET",
                        ).upper()
                    ),
                    "fields": fields,
                }
            ],
            "parameters": parameters,
        },
    }


def test_input(
    url,
    target,
):
    response = fetch_page(url)

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    elements = soup.find_all(
        [
            "input",
            "textarea",
            "select",
        ]
    )

    index = target.get(
        "index",
        0,
    )

    usable_elements = []

    for element in elements:
        input_type = element.get(
            "type",
            "text",
        )

        if input_type in {
            "hidden",
            "submit",
            "button",
        }:
            continue

        usable_elements.append(
            element
        )

    if index >= len(usable_elements):
        return {
            "success": False,
            "data": {
                "error": "Input not found.",
            },
        }

    element = usable_elements[index]

    parameter = element.get(
        "name"
    )

    parameters = []

    if is_valid_parameter(
        parameter
    ):
        parameters.append(
            parameter
        )

    return {
        "success": True,
        "data": {
            "input": {
                "name": element.get("name"),
                "id": element.get("id"),
                "type": element.get(
                    "type",
                    "text",
                ),
            },
            "parameters": parameters,
        },
    }