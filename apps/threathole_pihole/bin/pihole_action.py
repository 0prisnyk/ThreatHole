#!/usr/bin/env python3
import sys, json, traceback
from pihole_api import add_domain, del_domain, toggle_blocking, get_status

def main():
    try:
        payload = json.load(sys.stdin)  # Splunk шле JSON на stdin
        params  = payload.get("configuration", {}).get("parameters", {})

        action  = params.get("action")        # block | unblock | enable | disable | status
        domain  = params.get("domain") or ""
        regex   = str(params.get("regex", "false")).lower() in ("1","true","yes","on")
        minutes = params.get("minutes")

        if isinstance(minutes, str) and minutes.strip() == "":
            minutes = None
        if isinstance(minutes, str):
            try:
                minutes = int(minutes)
            except:
                minutes = None

        if action == "block":
            result = add_domain(domain, regex=regex, allow=False)
        elif action == "unblock":
            result = del_domain(domain, regex=regex, allow=False)
        elif action == "enable":
            result = toggle_blocking(True, minutes)
        elif action == "disable":
            result = toggle_blocking(False, minutes)
        elif action == "status":
            result = get_status()
        else:
            result = {"error": f"Unknown action: {action}"}

        print(json.dumps({"ok": True, "action": action, "result": result}))

    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "trace": traceback.format_exc()}))

if __name__ == "__main__":
    main()
