"""Bulk register rpow2.com accounts — curl_cffi TLS impersonation + subject-based email polling.

Strategy: CapSolver Turnstile token + curl_cffi Chrome TLS impersonation for /auth/request.
Key fix: after ImprovMX forwarding, TO header becomes the Gmail address, so we search by
Subject line instead: "rpow2" or "magic_link".

Usage:
    python _bulk_reg_v3.py <target> [<parallel>]

Env vars:
    CAPSOLVER_KEY, RPOW_DOMAIN, PROXY_HOST, PROXY_PORT,
    PROXY_USER, PROXY_PASS, IMAP_HOST, IMAP_PORT, IMAP_USER, IMAP_PASS
"""

import os, sys, json, time, random, base64, threading, imaplib, email, re, urllib.parse
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


def do_register_curl(email_addr, turnstile_token):
    """POST /auth/request using curl_cffi with Chrome TLS impersonation."""
    from curl_cffi import requests as curl

    body = json.dumps({"email": email_addr, "turnstile_token": turnstile_token})
    headers = {
        "Content-Type": "application/json",
        "Origin": PAGE_URL.rstrip("/"),
        "Referer": PAGE_URL,
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    }
    proxy = f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"

    try:
        resp = curl.post(
            f"{RPOW_API}/auth/request",
            data=body,
            headers=headers,
            proxy=proxy,
            impersonate="chrome",
            timeout=30,
            verify=False,
        )
        return resp.json(), resp.status_code
    except Exception as ex:
        return {"error": str(ex)}, 0


def poll_magic_link(email_addr, max_wait_s=MAIL_WAIT_S):
    """Poll Gmail IMAP for magic link email. Searches by Subject containing 'rpow2'
    since after ImprovMX forwarding the TO header becomes the Gmail address."""
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        try:
            M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            M.login(IMAP_USER, IMAP_PASS)
            M.select("INBOX")

            # Search by subject since TO header changes after forwarding
            _, data = M.search(None, 'SUBJECT "rpow2"')
            uids = data[0].split() if data and data[0] else []

            # Also search by subject "magic"
            _, data2 = M.search(None, 'SUBJECT "magic"')
            uids2 = data2[0].split() if data2 and data2[0] else []

            all_uids = list(dict.fromkeys(uids + uids2))  # dedupe, preserve order

            for uid in reversed(all_uids):
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
                subject = (msg.get("Subject") or "").lower()

                body = ""
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        try:
                            body += part.get_payload(decode=True).decode(
                                part.get_content_charset() or "utf-8", errors="ignore")
                        except Exception:
                            pass

                # Extract verify URL
                m = re.search(r'https?://[^\s"\'<>)]+/auth/verify\?token=[A-Za-z0-9_\-\.]+', body)
                if m:
                    M.logout()
                    return m.group(0)

            M.logout()
        except Exception as ex:
            log(f"[imap] poll err: {type(ex).__name__}: {ex}")
        time.sleep(MAIL_POLL_S)
    raise RuntimeError("magic link not received")


def verify_and_get_session(verify_url):
    """Visit verify URL using curl_cffi and extract rpow_session from cookies."""
    from curl_cffi import requests as curl

    proxy = f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        resp = curl.get(verify_url, headers=headers, proxy=proxy,
                        impersonate="chrome", timeout=30, verify=False, allow_redirects=True)
        for ck in resp.cookies:
            if ck.name == "rpow_session":
                return urllib.parse.unquote(ck.value)
        try:
            j = resp.json()
            for key in ("rpow_session", "session", "token", "sessionToken"):
                if key in j:
                    return j[key]
        except Exception:
            pass
        return None
    except Exception:
        return None


def append_account(rec):
    with FILE_LOCK:
        with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        with open(COOKIES_FILE, "a", encoding="utf-8") as f:
            f.write(rec["rpow_session"] + "\n")


def worker(wid):
    em = make_email()
    try:
        log(f"[w{wid}] solving Turnstile for {em} ...")
        tok = solve_turnstile()
        log(f"[w{wid}] Turnstile OK")
    except Exception as ex:
        log(f"[w{wid}] Turnstile fail: {ex}")
        return None

    log(f"[w{wid}] posting /auth/request (curl_cffi) ...")
    ar, status = do_register_curl(em, tok)
    if not ar or not ar.get("ok"):
        log(f"[w{wid}] auth rejected: {ar} (status={status})")
        return None
    log(f"[w{wid}] auth OK, polling mail")

    try:
        verify_url = poll_magic_link(em)
    except Exception as ex:
        log(f"[w{wid}] mail timeout: {ex}")
        return None

    log(f"[w{wid}] clicking verify ...")
    session = verify_and_get_session(verify_url)
    if not session:
        log(f"[w{wid}] no session from verify URL")
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
