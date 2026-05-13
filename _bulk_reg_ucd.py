"""Bulk register rpow2.com accounts — undetected-chromedriver + CapSolver.

Replaces curl_cffi with a real Chrome browser to defeat Cloudflare TLS
fingerprinting that was causing 403 on /auth/request even with valid
Turnstile tokens.

Usage:
    python _bulk_reg_ucd.py <target> [<parallel>]
    python _bulk_reg_ucd.py 5 2        # smoke test
    python _bulk_reg_ucd.py 1000 30    # bulk run

Env vars (override via .env or export):
    CAPSOLVER_KEY          CapSolver API key
    RPOW_DOMAIN             Email domain (e.g. piranhas.site)
    PROXY_HOST              Proxy host (e.g. gw.dataimpulse.com)
    PROXY_PORT              Proxy port (e.g. 10000)
    PROXY_USER              Proxy username
    PROXY_PASS              Proxy password
    IMAP_HOST               IMAP host (imap.gmail.com)
    IMAP_PORT               IMAP port (993)
    IMAP_USER               Gmail address
    IMAP_PASS               Gmail app password
    MAIL_WAIT_S             Max seconds to wait for magic link (default 600)
    MAIL_POLL_S             IMAP poll interval (default 8)

Outputs:
    accounts_bulk.jsonl    one JSON per line (append)
    cookies_bulk.txt        one rpow_session per line (append)
"""

import os, sys, json, time, random, base64, threading, imaplib, email, re, urllib.parse, secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import warnings
warnings.filterwarnings("ignore")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---- rpow2 target ----
SITEKEY = "0x4AAAAAADLyZ9ztTUV1Pm1F"
PAGE_URL = "https://rpow2.com/"
RPOW_API = "https://api.rpow2.com"

# ---- credentials from env ----
CAPSOLVER_KEY = os.environ.get("CAPSOLVER_KEY", "YOUR_CAPSOLVER_KEY")
EMAIL_DOMAIN = os.environ.get("RPOW_DOMAIN", "piranhas.site")

PROXY_HOST = os.environ.get("PROXY_HOST", "gw.dataimpulse.com")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "10000"))
PROXY_USER = os.environ.get("PROXY_USER", "YOUR_PROXY_USER")
PROXY_PASS = os.environ.get("PROXY_PASS", "YOUR_PROXY_PASS")

IMAP_HOST = os.environ.get("IMAP_HOST", "imap.gmail.com")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
IMAP_USER = os.environ.get("IMAP_USER", "YOUR_GMAIL@gmail.com")
IMAP_PASS = os.environ.get("IMAP_PASS", "YOUR_16CHAR_APP_PASS")

# ---- tuning ----
MAIL_WAIT_S = int(os.environ.get("MAIL_WAIT_S", "600"))
MAIL_POLL_S = int(os.environ.get("MAIL_POLL_S", "8"))
CAP_TIMEOUT_S = int(os.environ.get("CAP_TIMEOUT_S", "300"))
HTTP_TIMEOUT_S = int(os.environ.get("HTTP_TIMEOUT_S", "60"))

ACCOUNTS_FILE = "accounts_bulk.jsonl"
COOKIES_FILE = "cookies_bulk.txt"

# ---- shared state ----
LOG_LOCK = threading.Lock()
FILE_LOCK = threading.Lock()
STATS = {"ok": 0, "fail": 0, "started_at": time.time()}

ADJ = ("amber arctic azure bold brave breezy bright bronze calm classic clever "
       "cobalt coral cosmic crimson dusty fierce frosty gentle glossy golden happy "
       "humble ivory jade jolly lazy lucky mellow mellow mystic neon noble pinky "
       "pure quick quiet quirky retro rocky royal rustic sage scarlet shiny silky "
       "silver snappy stormy sunny swift tropic urban velvet vintage violet wild "
       "wise witty").split()
ANIMAL = ("badger beaver bison bobcat capybara caracal cheetah civet condor cougar "
          "crane crow deer dingo dolphin echidna elk falcon ferret finch flamingo "
          "fox genet hare horse ibis iguana jaguar kiwi koala leopard lion lynx "
          "macaw manatee marten meerkat mongoose moose narwhal numbat ocelot orca "
          "otter owl panda parrot pelican penguin platypus puffin puma rabbit robin "
          "salamander seal serval shark sparrow stoat stork tapir turtle viper "
          "walrus weasel wolf wombat").split()


def log(msg):
    with LOG_LOCK:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def make_email():
    return f"{random.choice(ADJ)}_{random.choice(ANIMAL)}{random.randint(10,99)}@{EMAIL_DOMAIN}".lower()


def solve_turnstile():
    """CapSolver AntiTurnstileTaskProxyLess."""
    create = requests.post("https://api.capsolver.com/createTask", json={
        "clientKey": CAPSOLVER_KEY,
        "task": {
            "type": "AntiTurnstileTaskProxyLess",
            "websiteURL": PAGE_URL,
            "websiteKey": SITEKEY,
        },
    }, timeout=30).json()
    if not create.get("taskId"):
        raise RuntimeError(f"capsolver createTask: {create}")
    task_id = create["taskId"]
    deadline = time.time() + CAP_TIMEOUT_S
    while time.time() < deadline:
        time.sleep(3)
        r = requests.post("https://api.capsolver.com/getTaskResult", json={
            "clientKey": CAPSOLVER_KEY, "taskId": task_id,
        }, timeout=30).json()
        if r.get("status") == "ready":
            return r["solution"]["token"]
        if r.get("status") == "failed" or r.get("errorId"):
            raise RuntimeError(f"capsolver: {r}")
    raise RuntimeError("capsolver timeout")


def get_chrome_driver(proxy_url):
    """Start a headless Chrome with proxy. Returns the driver instance."""
    import undetected_chromedriver as uc

    options = uc.ChromeOptions()
    # Headless but with real fingerprint
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-blink-features=AutomationControlled")

    # Proxy with authentication
    proxy_parts = proxy_url.split("@")
    if len(proxy_parts) == 2:
        auth, host_port = proxy_parts
        user, pw = auth.replace("http://", "").split(":")
        host, port = host_port.split(":")
        plugin_path = create_proxy_auth_plugin(host, int(port), user, pw)
        options.add_extension(plugin_path)
    else:
        options.add_argument(f"--proxy-server={proxy_url}")

    try:
        driver = uc.Chrome(options=options, version_main=None, use_subprocess=True)
    except Exception:
        # Fallback: try without subprocess mode
        driver = uc.Chrome(options=options, version_main=None)
    return driver


def create_proxy_auth_plugin(host, port, user, password):
    """Create a Chrome proxy auth extension (PAC file workaround)."""
    import zipfile, os, base64

    manifest_json = json.dumps({
        "version": "1.0.0",
        "manifest_version": 2,
        "name": "Proxy Auth",
        "permissions": ["proxy", "tabs", "webRequest", "webRequestAuthProvider"],
        "background": {"scripts": ["background.js"]},
        "minimum_chrome_version": "77.0"
    })

    background_js = f"""
var config = {{
    mode: "fixed_servers",
    rules: {{
        singleProxy: {{
            scheme: "http",
            host: "{host}",
            port: {port}
        }}
    }}
}};
chrome.proxy.settings.set({{value: config, scope: "regular"}}, () => {{}});
function callback(details) {{
    return {{
        authCredentials: {{
            username: "{user}",
            password: "{password}"
        }}
    }};
}}
chrome.webRequest.onAuthRequired.addListener(callback, {{urls: ["<all_urls>"]}}, ["asyncBlocking"]);
"""

    plugin_dir = os.path.join(os.path.dirname(__file__), f"_proxy_auth_{os.getpid()}")
    os.makedirs(plugin_dir, exist_ok=True)
    with open(os.path.join(plugin_dir, "manifest.json"), "w") as f:
        f.write(manifest_json)
    with open(os.path.join(plugin_dir, "background.js"), "w") as f:
        f.write(background_js)

    zip_path = plugin_dir + ".zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.write(os.path.join(plugin_dir, "manifest.json"), "manifest.json")
        zf.write(os.path.join(plugin_dir, "background.js"), "background.js")

    return zip_path


def do_register(email_addr, turnstile_token, driver):
    """Use Chrome to hit /auth/request with the Turnstile token."""
    try:
        # Navigate to rpow2.com first to set Cloudflare cookies
        driver.get("https://rpow2.com/")
        time.sleep(2)

        # Execute the auth request via fetch in the browser context
        # We inject the token into the page and submit via fetch
        script = f"""
        return fetch("{RPOW_API}/auth/request", {{
            method: "POST",
            headers: {{
                "Content-Type": "application/json",
                "Origin": "https://rpow2.com",
                "Referer": "https://rpow2.com/",
                "Accept": "application/json, text/plain, */*"
            }},
            body: JSON.stringify({{
                "email": "{email_addr}",
                "turnstile_token": "{turnstile_token}"
            }})
        }}).then(r => r.json()).catch(e => ({{ error: e.message }}));
        """
        result = driver.execute_script(script)
        return result
    except Exception as ex:
        return {"error": str(ex)}


def poll_magic_link(recipient, max_wait_s=MAIL_WAIT_S):
    """Search Gmail IMAP by TO header. Use BODY.PEEK to NOT mark Seen."""
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        try:
            M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            M.login(IMAP_USER, IMAP_PASS)
            M.select("INBOX")
            typ, data = M.search(None, f'(TO "{recipient}")')
            uids = data[0].split() if data and data[0] else []
            for uid in reversed(uids):
                typ, msg_data = M.fetch(uid, "(BODY.PEEK[])")
                if not msg_data:
                    continue
                raw = None
                for resp in msg_data:
                    if isinstance(resp, tuple) and len(resp) >= 2 and isinstance(resp[1], (bytes, bytearray)):
                        raw = resp[1]
                        break
                if raw is None:
                    continue
                msg = email.message_from_bytes(raw)
                from_addr = (msg.get("From") or "").lower()
                if "rpow2" not in from_addr:
                    continue
                body_text = ""
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        try:
                            body_text += part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8", errors="ignore")
                        except Exception:
                            pass
                m = re.search(r'https?://api\.rpow2\.com/auth/verify\?token=([A-Za-z0-9_\-\.]+)', body_text)
                if not m:
                    m = re.search(r'https?://[^\s"\'<>)]+/auth/verify\?token=([A-Za-z0-9_\-\.]+)', body_text)
                if m:
                    M.logout()
                    return m.group(0), m.group(1)
            M.logout()
        except Exception as ex:
            log(f"[imap] poll err: {type(ex).__name__}: {ex}")
        time.sleep(MAIL_POLL_S)
    raise RuntimeError("magic link not received in time")


def verify_click(verify_url, driver):
    """Use Chrome to click the verify URL and extract rpow_session cookie."""
    try:
        driver.get(verify_url)
        time.sleep(3)

        # Check for rpow_session cookie
        cookies = driver.get_cookies()
        for ck in cookies:
            if ck['name'] == 'rpow_session':
                return urllib.parse.unquote(ck['value'])

        # Also try to read from page body (JSON response)
        try:
            body = driver.find_element("tag name", "body").text
            import json as js
            j = js.loads(body)
            for k in ("rpow_session", "token", "access_token", "sessionToken", "session"):
                if k in j:
                    return j[k]
        except Exception:
            pass

        # Try Location header via redirect
        current_url = driver.current_url
        if "token=" in current_url:
            parsed = urllib.parse.urlparse(current_url)
            qs = urllib.parse.parse_qs(parsed.query)
            for k in ("s", "token", "session"):
                if k in qs:
                    return qs[k][0]

        raise RuntimeError(f"no session token in verify response at {current_url}")
    except Exception as ex:
        raise RuntimeError(f"verify_click: {ex}")


def append_account(rec):
    with FILE_LOCK:
        with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        with open(COOKIES_FILE, "a", encoding="utf-8") as f:
            f.write(rec["rpow_session"] + "\n")


def build_proxy_url():
    """Build DataImpulse proxy URL with auth."""
    return f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"


def worker(worker_id):
    proxy_url = build_proxy_url()
    em = make_email()
    driver = None

    try:
        # Step 1: Solve Turnstile via CapSolver
        log(f"[w{worker_id}] solving Turnstile for {em} ...")
        tok = solve_turnstile()
        log(f"[w{worker_id}] Turnstile token obtained")
    except Exception as ex:
        log(f"[w{worker_id}] turnstile fail: {ex}")
        return None

    try:
        # Step 2: Start Chrome with proxy, do auth/request
        log(f"[w{worker_id}] starting Chrome (proxy: {PROXY_HOST}:{PROXY_PORT}) ...")
        driver = get_chrome_driver(proxy_url)

        log(f"[w{worker_id}] hitting /auth/request ...")
        ar = do_register(em, tok, driver)
        driver.quit()
        driver = None

        if not ar.get("ok"):
            log(f"[w{worker_id}] auth rejected: {ar}")
            return None
        log(f"[w{worker_id}] {em} -> auth ok, waiting magic link")
    except Exception as ex:
        log(f"[w{worker_id}] auth/Chrome fail {em}: {ex}")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None

    # Step 3: Poll for magic link
    try:
        verify_url, verify_token = poll_magic_link(em)
    except Exception as ex:
        log(f"[w{worker_id}] mail fail {em}: {ex}")
        return None

    # Step 4: Click verify URL in Chrome
    try:
        log(f"[w{worker_id}] clicking verify URL ...")
        driver = get_chrome_driver(proxy_url)
        session_token = verify_click(verify_url, driver)
        driver.quit()
        driver = None
    except Exception as ex:
        log(f"[w{worker_id}] verify fail {em}: {ex}")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None

    # Step 5: Decode JWT exp
    payload, exp_iso = None, None
    try:
        b64 = session_token.split(".")[1].replace("-", "+").replace("_", "/")
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        payload = json.loads(base64.b64decode(b64).decode("utf-8"))
        if payload.get("exp"):
            exp_iso = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(payload["exp"]))
    except Exception:
        pass

    rec = {
        "email": em,
        "verifyUrl": verify_url,
        "verifyToken": verify_token,
        "rpow_session": session_token,
        "sessionToken": session_token,
        "sessionPayload": payload,
        "sessionExpiresAt": exp_iso,
        "verifiedAt": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
    }
    append_account(rec)
    log(f"[w{worker_id}] {em} -> SUCCESS")
    return rec


def main():
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    parallel = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    log(f"target={target} parallel={parallel} domain={EMAIL_DOMAIN}")
    log(f"proxy={PROXY_HOST}:{PROXY_PORT}  imap={IMAP_USER}")

    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futures = set()
        submitted = 0
        wid = 0
        while STATS["ok"] < target:
            while len(futures) < parallel and submitted < target * 10:
                wid += 1
                submitted += 1
                futures.add(ex.submit(worker, wid))
            done = {f for f in futures if f.done()}
            for f in done:
                try:
                    if f.result():
                        STATS["ok"] += 1
                    else:
                        STATS["fail"] += 1
                except Exception as e:
                    STATS["fail"] += 1
                    log(f"[main] exc: {e}")
            futures -= done
            if not done:
                time.sleep(1)
            el = time.time() - STATS["started_at"]
            rate = STATS["ok"] / el * 60 if el > 0 else 0
            eta = (target - STATS["ok"]) / max(rate / 60, 1e-6) / 60 if rate > 0 else float("inf")
            if (STATS["ok"] + STATS["fail"]) > 0 and (STATS["ok"] + STATS["fail"]) % parallel == 0:
                log(f"[main] ok={STATS['ok']}/{target} fail={STATS['fail']} rate={rate:.1f}/min eta={eta:.1f}min")
    el = time.time() - STATS["started_at"]
    log(f"DONE ok={STATS['ok']} fail={STATS['fail']} elapsed={el/60:.1f}min "
        f"rate={STATS['ok']/el*60:.1f}/min")
    log(f"wrote to {COOKIES_FILE} and {ACCOUNTS_FILE}")


if __name__ == "__main__":
    main()