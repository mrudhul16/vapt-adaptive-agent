from playwright.sync_api import sync_playwright

with sync_playwright() as p:

    browser = p.chromium.launch(headless=False)

    page = browser.new_page()

    page.goto(
        "http://localhost:3000/#/login",
        wait_until="domcontentloaded"
    )

    page.wait_for_timeout(1000)

    print("\nALL INPUTS")
    print("=" * 40)

    inputs = page.locator("input")

    for i in range(inputs.count()):

        field = inputs.nth(i)

        print(
            "\nINDEX:", i,
            "\nTAG:", field.evaluate("(e) => e.tagName"),
            "\nTYPE:", field.get_attribute("type"),
            "\nNAME:", field.get_attribute("name"),
            "\nID:", field.get_attribute("id"),
            "\nPLACEHOLDER:", field.get_attribute("placeholder"),
            "\nAUTOCOMPLETE:", field.get_attribute("autocomplete")
        )

    print("\nLOGIN FORM HTML")
    print("=" * 40)

    forms = page.locator("form")

    print("Forms:", forms.count())

    for i in range(forms.count()):

        print(
            forms.nth(i).evaluate(
                "(e) => e.outerHTML"
            )
        )

    input("\nPress ENTER to close...")

    browser.close()