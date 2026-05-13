"""Bulk register rpow2.com accounts — undetected-chromedriver + CapSolver.

Usage:
    python _bulk_reg_uc.py <target> [<parallel>]

Env vars:
    CAPSOLVER_KEY, RPOW_DOMAIN, PROXY_HOST, PROXY_PORT,
    PROXY_USER, PROXY_PASS, IMAP_HOST, IMAP_PORT, IMAP_USER, IMAP_PASS
    MAIL_WAIT_S, MAIL_POLL_S, CAP_TIMEOUT_S
"""

import os, sys, json, time, random, base64, threading, imaplib, email, re, urllib.parse, tempfile
from concurrent.futures import ThreadPoolExecutor
import requests
import warnings
warnings.filterwarnings("ignore")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SITEKEY = "0x4AAAAAADLyZ9ztTUV1Pm1F"
PAGE_URL = "https://rpow2.com/"
RPOW_API = "https://api.rpow2.com"

CAPSOLVER_KEY = os.environ.get("CAPSOLVER_KEY", "")
EMAIL_DOMAIN = os.environ.get("RPOW_DOMAIN", "piranhas.site")
PROXY_HOST = os.environ.get("PROXY_HOST", "gw.dataimpulse.com")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "10000"))
PROXY_USER = os.environ.get("PROXY_USER", "")
PROXY_PASS = os.environ.get("PROXY_PASS", "")
IMAP_HOST = os.environ.get("IMAP_HOST", "imap.gmail.com")
IMAP_PORT = int(os.environ.get("IMAP_PORT", "993"))
IMAP_USER = os.environ.get("IMAP_USER", "")
IMAP_PASS = os.environ.get("IMAP_PASS", "")

MAIL_WAIT_S = int(os.environ.get("MAIL_WAIT_S", "600"))
MAIL_POLL_S = int(os.environ.get("MAIL_POLL_S", "8"))
CAP_TIMEOUT_S = int(os.environ.get("CAP_TIMEOUT_S", "300"))

ACCOUNTS_FILE = "accounts_bulk.jsonl"
COOKIES_FILE = "cookies_bulk.txt"

LOG_LOCK = threading.Lock()
FILE_LOCK = threading.Lock()
STATS = {"ok": 0, "fail": 0, "started_at": time.time()}

ADJ = ("amber arctic azure bold brave breezy bright bronze calm classic clever "
       "cobalt coral cosmic crimson dusty fierce frosty gentle glossy golden happy "
       "humble ivory jade jolly lazy lucky mellow mystic neon noble pinky "
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


def make_proxy_auth_extension(host, port, user, password):
    """Return path to a Chrome proxy-auth extension zip."""
    import zipfile
    plugin_dir = tempfile.mkdtemp(prefix="proxy_auth_")
    manifest = {
        "version": "1.0.0",
        "manifest_version": 2,
        "name": "Proxy Auth",
        "permissions": ["proxy", "tabs", "webRequest", "webRequestAuthProvider"],
        "background": {"scripts": ["background.js"]},
        "minimum_chrome_version": "77.0"
    }
    bg = f"""
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
    return {{authCredentials: {{username: "{user}", password: "{password}"}}}};
}}
chrome.webRequest.onAuthRequired.addListener(callback, {{urls: ["<all_urls>"]}}, ["asyncBlocking"]);
"""
    with open(os.path.join(plugin_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f)
    with open(os.path.join(plugin_dir, "background.js"), "w") as f:
        f.write(bg)
    zip_path = os.path.join(plugin_dir, "proxy_auth.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(os.path.join(plugin_dir, "manifest.json"), "manifest.json")
        zf.write(os.path.join(plugin_dir, "background.js"), "background.js")
    return zip_path


def new_driver(proxy_host, proxy_port, proxy_user, proxy_pass):
    """Create a fresh undetected_chromedriver instance with proxy auth."""
    import undetected_chromedriver as uc

    ext_path = make_proxy_auth_extension(proxy_host, proxy_port, proxy_user, proxy_pass)

    options = uc.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--mute-audio")
    options.add_argument(f"--load-extension={ext_path}")

    # undetected_chromedriver handles fingerprinting
    driver = uc.Chrome(options=options, version_main=None, use_subprocess=True)
    driver.set_page_load_timeout(40)
    return driver


def do_register(email_addr, turnstile_token, driver):
    try:
        driver.get(PAGE_URL)
        time.sleep(4)  # Let Cloudflare challenges settle

        script = f"""
        return fetch("{RPOW_API}/auth/request", {{
            method: "POST",
            headers: {{
                "Content-Type": "application/json",
                "Origin": "{PAGE_URL.rstrip('/')}",
                "Referer": "{PAGE_URL}",
                "Accept": "application/json, text/plain, */*"
            }},
            body: JSON.stringify({{
                "email": "{email_addr}",
                "turnstile_token": "{turnstile_token}"
            }})
        }}).then(r => r.json()).catch(e => ({{ error: String(e) }}));
        """
        return driver.execute_script(script)
    except Exception as ex:
        return {"error": str(ex)}


def poll_magic_link(recipient, max_wait_s=MAIL_WAIT_S):
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        try:
            M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            M.login(IMAP_USER, IMAP_PASS)
            M.select("INBOX")
            _, data = M.search(None, f'(TO "{recipient}")')
            uids = data[0].split() if data and data[0] else []
            for uid in reversed(uids):
                _, msg_data = M.fetch(uid, "(BODY.PEEK[])")
                if not msg_data or not msg_data[0]:
                    continue
                raw = None
                for resp in msg_data:
                    if isinstance(resp, tuple) and len(resp) >= 2:
                        raw = resp[1]
                        break
                if not raw:
                    continue
                msg = email.message_from_bytes(raw)
                from_lower = (msg.get("From") or "").lower()
                if "rpow2" not in from_lower:
                    continue
                body = ""
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        try:
                            body += part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8", errors="ignore")
                        except Exception:
                            pass
                m = re.search(r'https?://[^\s"\'<>)]+/auth/verify\?token=[A-Za-z0-9_\-\.]+', body)
                if m:
                    M.logout()
                    return m.group(0)
            M.logout()
        except Exception as ex:
            log(f"[imap] poll err: {type(ex).__name__}: {ex}")
        time.sleep(MAIL_POLL_S)
    raise RuntimeError("magic link not received")


def verify_and_get_session(verify_url, driver):
    try:
        driver.get(verify_url)
        time.sleep(4)
        for ck in driver.get_cookies():
            if ck["name"] == "rpow_session":
                return urllib.parse.unquote(ck["value"])
        try:
            body = driver.find_element("tag name", "body").text
            j = json.loads(body)
            for key in ("rpow_session", "session", "token", "sessionToken"):
                if key in j:
                    return j[key]
        except Exception:
            pass
        parsed = urllib.parse.urlparse(driver.current_url)
        qs = urllib.parse.parse_qs(parsed.query)
        for key in ("s", "token", "session"):
            if key in qs:
                return qs[key][0]
        raise RuntimeError(f"no session at {driver.current_url}")
    except Exception as ex:
        raise RuntimeError(f"verify: {ex}")


def append_account(rec):
    with FILE_LOCK:
        with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        with open(COOKIES_FILE, "a", encoding="utf-8") as f:
            f.write(rec["rpow_session"] + "\n")


def worker(wid):
    driver = None
    em = make_email()
    try:
        log(f"[w{wid}] solving Turnstile for {em} ...")
        tok = solve_turnstile()
        log(f"[w{wid}] Turnstile OK")
    except Exception as ex:
        log(f"[w{wid}] Turnstile fail: {ex}")
        return None

    try:
        log(f"[w{wid}] starting Chrome ...")
        driver = new_driver(PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASS)
        log(f"[w{wid}] posting /auth/request ...")
        ar = do_register(em, tok, driver)
        driver.quit()
        driver = None
        if not ar or not ar.get("ok"):
            log(f"[w{wid}] auth rejected: {ar}")
            return None
        log(f"[w{wid}] auth OK, polling mail")
    except Exception as ex:
        log(f"[w{wid}] Chrome error: {ex}")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None

    try:
        verify_url = poll_magic_link(em)
    except Exception as ex:
        log(f"[w{wid}] mail timeout: {ex}")
        return None

    try:
        log(f"[w{wid}] clicking verify ...")
        driver = new_driver(PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASS)
        session = verify_and_get_session(verify_url, driver)
        driver.quit()
        driver = None
    except Exception as ex:
        log(f"[w{wid}] verify error: {ex}")
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return None

    exp_iso = None
    try:
        parts = session.split(".")
        if len(parts) >= 2:
            b64 = parts[1].replace("-", "+").replace("_", "/")
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            payload = json.loads(base64.b64decode(b64).decode())
            if payload.get("exp"):
                exp_iso = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(payload["exp"]))
    except Exception:
        pass

    rec = {
        "email": em,
        "verifyUrl": verify_url,
        "rpow_session": session,
        "sessionToken": session,
        "sessionExpiresAt": exp_iso,
        "verifiedAt": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
    }
    append_account(rec)
    log(f"[w{wid}] {em} -> SUCCESS")
    return rec


def main():
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    parallel = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    log(f"target={target} parallel={parallel} domain={EMAIL_DOMAIN}")
    log(f"proxy={PROXY_HOST}:{PROXY_PORT}  imap={IMAP_USER}")

    wid = 0
    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futures = {}
        while STATS["ok"] < target:
            while len(futures) < parallel and STATS["ok"] + STATS["fail"] < target * 10:
                wid += 1
                f = ex.submit(worker, wid)
                futures[f] = wid

            done = [f for f in futures if f.done()]
            if not done:
                time.sleep(1)
                continue

            for f in done:
                wn = futures.pop(f)
                try:
                    if f.result():
                        STATS["ok"] += 1
                    else:
                        STATS["fail"] += 1
                except Exception as e:
                    STATS["fail"] += 1
                    log(f"[main] w{wn} exc: {e}")

            el = time.time() - STATS["started_at"]
            rate = STATS["ok"] / max(el, 1) * 60
            log(f"[main] ok={STATS['ok']}/{target} fail={STATS['fail']} rate={rate:.1f}/min")

    el = time.time() - STATS["started_at"]
    log(f"DONE ok={STATS['ok']} fail={STATS['fail']} elapsed={el/60:.1f}min")
    log(f"wrote to {COOKIES_FILE} and {ACCOUNTS_FILE}")


if __name__ == "__main__":
    main()
