from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

OUTPUT = Path("output/playwright")


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    console_errors: list[str] = []
    failed_requests: list[str] = []
    with sync_playwright() as playwright:
        # Reuse the locally installed Edge channel so the smoke test does not require
        # a repository-specific browser binary.
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on(
            "console",
            lambda message: (
                console_errors.append(message.text) if message.type == "error" else None
            ),
        )
        page.on("requestfailed", lambda request: failed_requests.append(request.url))
        page.goto("http://127.0.0.1:8501", wait_until="networkidle")
        page.get_by_text("网络安全风险态势总览", exact=True).wait_for()
        page.get_by_text("已审计关系", exact=True).wait_for()
        page.get_by_text("数据快照", exact=False).wait_for()
        page.wait_for_timeout(750)
        page.screenshot(path=str(OUTPUT / "overview.png"), full_page=True)

        for page_name, expected in [
            ("综合情报检索", "返回"),
            ("安全事件", "SolarWinds"),
            ("关系探索", "跳数"),
            ("趋势研究", "政策主题变化"),
            ("RAG 研究助手", "研究问题"),
            ("专题报告与场景示例", "数据快照"),
        ]:
            page.get_by_text(page_name, exact=True).first.click()
            page.wait_for_load_state("networkidle")
            page.get_by_text(expected, exact=False).first.wait_for()

        page.screenshot(path=str(OUTPUT / "reports.png"), full_page=True)
        browser.close()
    benign_console_fragments = (
        "favicon",
        "Failed to fetch metrics config",
        "Undefined metrics config",
        "Failed to load resource: net::ERR_NETWORK_ACCESS_DENIED",
    )
    actionable = [
        message
        for message in console_errors
        if not any(fragment.lower() in message.lower() for fragment in benign_console_fragments)
    ]
    actionable_requests = [
        url
        for url in failed_requests
        if not any(host in url for host in ("streamlit.io", "segment.com"))
    ]
    if actionable or actionable_requests:
        raise AssertionError("Browser errors: " + " | ".join(actionable + actionable_requests))
    print("UI smoke test passed: overview, search, events, relations, trends, RAG, reports")


if __name__ == "__main__":
    main()
