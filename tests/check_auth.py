from playwright.sync_api import sync_playwright

URL = "http://localhost:3000"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)

    context = browser.new_context()
    page = context.new_page()

    page.goto(URL)
    page.wait_for_timeout(2000)

    print("\nBEFORE LOGIN")
    print("=" * 40)
    print("URL:", page.url)
    print("Cookies:", context.cookies())
    print("localStorage:", page.evaluate("Object.fromEntries(Object.entries(localStorage))"))
    print("sessionStorage:", page.evaluate("Object.fromEntries(Object.entries(sessionStorage))"))

    print("\nLOGIN MANUALLY IN THE BROWSER")
    print("Use your normal Juice Shop login.")
    input("\nPress ENTER after you are successfully logged in...")

    print("\nAFTER LOGIN")
    print("=" * 40)
    print("URL:", page.url)
    print("Cookies:", context.cookies())
    print("localStorage:", page.evaluate("Object.fromEntries(Object.entries(localStorage))"))
    print("sessionStorage:", page.evaluate("Object.fromEntries(Object.entries(sessionStorage))"))

    try:
        response = page.request.get(
            "http://localhost:3000/rest/whoami"
        )

        print("\nWHOAMI")
        print("=" * 40)
        print("Status:", response.status)
        print("Body:", response.text())

    except Exception as e:
        print("\nWHOAMI ERROR:", e)

    input("\nPress ENTER to close...")
    browser.close()