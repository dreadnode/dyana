import argparse
import os
from typing import Any

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from dyana import Profiler  # type: ignore[attr-defined]

CHROMIUM_BROWSER_PATH = "/usr/bin/chromium-browser"
CHROMIUM_DRIVER_PATH = "/usr/lib/chromium/chromedriver"


def setup_chrome_options(performance_log: bool) -> webdriver.ChromeOptions:
    chrome_options = webdriver.ChromeOptions()

    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")

    # disable Google services and non-critical features that can cause hangs
    chrome_options.add_argument("--disable-sync")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-domain-reliability")
    chrome_options.add_argument("--disable-client-side-phishing-detection")
    chrome_options.add_argument("--disable-component-update")
    chrome_options.binary_location = CHROMIUM_BROWSER_PATH

    # force DNS lookups for each request
    chrome_options.add_argument("--dns-prefetch-disable")
    chrome_options.add_argument("--disable-http-cache")
    chrome_options.add_argument("--disable-browser-side-navigation")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])

    if performance_log:
        # network logging prefs
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL", "browser": "ALL", "network": "ALL"})

    return chrome_options


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Profile website performance")
    parser.add_argument("--url", help="URL to open", required=True)
    parser.add_argument("--wait-for", help="CSS selector to wait for", default=None)
    parser.add_argument(
        "--wait-for-timeout", help="Timeout to wait for the CSS selectorin seconds", type=int, default=30
    )
    parser.add_argument("--screenshot", help="Save a screenshot of the page", action="store_true")
    parser.add_argument("--performance-log", help="Enable performance logging", action="store_true")
    args = parser.parse_args()

    # normalize URL - https:// if protocol is missing
    if "://" not in args.url:
        args.url = f"https://{args.url}"

    profiler: Profiler = Profiler()
    driver: webdriver.Chrome | None = None

    try:
        chrome_options = setup_chrome_options(args.performance_log)
        service = webdriver.ChromeService(executable_path=CHROMIUM_DRIVER_PATH)
        driver = webdriver.Chrome(options=chrome_options, service=service)

        profiler.on_stage("after_init")

        # set shorter timeouts
        driver.set_page_load_timeout(15)
        driver.implicitly_wait(5)

        try:
            driver.get(args.url)
        except TimeoutException:
            profiler.track_error("page_load", f"Timeout loading page: {args.url}")
            # continue execution to capture any partial data

        if args.performance_log:
            driver_with_logs: Any = driver
            network_logs = driver_with_logs.get_log("performance")
            profiler.track_extra("network_logs", network_logs)
            browser_logs = driver_with_logs.get_log("browser")
            profiler.track_extra("browser_logs", browser_logs)

        profiler.on_stage("after_load")

        if args.wait_for:
            try:
                WebDriverWait(driver, args.wait_for_timeout).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, args.wait_for))
                )
            except TimeoutException:
                profiler.track_error("wait", f"Timeout waiting for element: {args.wait_for}")

        if args.screenshot:
            try:
                driver.get_screenshot_as_file("/tmp/screenshot.png")
                os.environ["DYANA_SAVE"] = "/tmp/screenshot.png"
            except Exception as e:
                profiler.track_error("screenshot", str(e))

        profiler.on_stage("after_profiling")

    except Exception as e:
        profiler.track_error("chrome", str(e))
    finally:
        try:
            if driver:
                driver.quit()
        except Exception as _:
            pass
