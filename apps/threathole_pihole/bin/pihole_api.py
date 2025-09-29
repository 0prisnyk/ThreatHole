#!/usr/bin/env python3
import requests, json, argparse, os, time
from urllib.parse import quote

# >>> Налаштування <<<
PIHOLE = "http://$IP_OF_YOUR_PI$/api" 
PASSWORD = "$PASSWORD_TO_PIHOLE_WEB$"
VERIFY_SSL = False 
SID_FILE = "/opt/splunk/var/run/pihole_sid"

# --------- AUTH -----------
def login():
    if os.path.exists(SID_FILE):
        age = time.time() - os.path.getmtime(SID_FILE)
        if age < 250: 
            with open(SID_FILE) as f:
                return f.read().strip()


    r = requests.post(f"{PIHOLE}/auth", json={"password": PASSWORD}, verify=VERIFY_SSL)
    r.raise_for_status()
    sid = r.json()["session"]["sid"]

    with open(SID_FILE, "w") as f:
        f.write(sid)
    return sid

# --------- FUNCTIONS -----------
def add_domain(domain, regex=False, allow=False):
    sid = login()
    type_ = "allow" if allow else "deny"
    kind = "regex" if regex else "exact"
    r = requests.post(
        f"{PIHOLE}/domains/{type_}/{kind}",
        headers={"X-FTL-SID": sid},
        json={"domain": domain},
        verify=VERIFY_SSL
    )
    return {"status": r.status_code, "location": r.headers.get("Location"), "body": (r.json() if r.content else None)}

def del_domain(domain, regex=False, allow=False):
    sid = login()
    type_ = "allow" if allow else "deny"
    kind = "regex" if regex else "exact"
    encoded = quote(domain, safe="") 
    r = requests.delete(
        f"{PIHOLE}/domains/{type_}/{kind}/{encoded}",
        headers={"X-FTL-SID": sid},
        verify=VERIFY_SSL
    )
    return {"status": r.status_code, "body": (r.json() if r.content else r.text)}

def toggle_blocking(enable=True, minutes=None):
    sid = login()
    payload = {"blocking": enable}
    if minutes:
        payload["timer"] = int(minutes) * 60 
    r = requests.post(
        f"{PIHOLE}/dns/blocking",
        headers={"X-FTL-SID": sid},
        json=payload,
        verify=VERIFY_SSL
    )
    return r.json()

def get_status():
    sid = login()
    r = requests.get(f"{PIHOLE}/dns/blocking", headers={"X-FTL-SID": sid}, verify=VERIFY_SSL)
    return r.json()

# --------- CLI HANDLER -----------
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--action", required=True, choices=["block","unblock","enable","disable","status"])
    p.add_argument("--domain")
    p.add_argument("--regex", action="store_true")
    p.add_argument("--allow", action="store_true")   # опціонально: робота з allowlist
    p.add_argument("--minutes", type=int)
    args = p.parse_args()

    if args.action in ["block","unblock"] and not args.domain:
        p.error("--domain is required for block/unblock")

    if args.action == "block":
        print(json.dumps(add_domain(args.domain, regex=args.regex, allow=args.allow)))
    elif args.action == "unblock":
        print(json.dumps(del_domain(args.domain, regex=args.regex, allow=args.allow)))
    elif args.action == "enable":
        print(json.dumps(toggle_blocking(True, args.minutes)))
    elif args.action == "disable":
        print(json.dumps(toggle_blocking(False, args.minutes)))
    elif args.action == "status":
        print(json.dumps(get_status()))
