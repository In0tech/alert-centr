

def c_rounding(value, unit):
    value = float(value)
    if   value >= 1000000000:
        return f"{(value/1000000000):.2f} G{unit}"
    elif value >= 1000000:
        return f"{(value/1000000):.2f} M{unit}"
    elif value >= 1000:
        return f"{(value/1000):.2f} K{unit}"
    else:
        return f"{value:.2f} {unit}"


def c_compact(value):
    """Compact count formatting (no unit): 123, 1.23k, 1.23M, 1.23G.

    Mirrors the ag-grid compact formatter used for the WAF/DP block columns
    so the table and the alert-details text blocks render counts identically.
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    if   v >= 1_000_000_000:
        return f"{v/1_000_000_000:.2f}G"
    elif v >= 1_000_000:
        return f"{v/1_000_000:.2f}M"
    elif v >= 1_000:
        return f"{v/1_000:.2f}k"
    else:
        return f"{int(v)}"


def sec_to_str(sec):
    try:
        sec = int(sec)
    except (TypeError, ValueError):
        return str(sec)
    if sec > 86400:
        return f"{sec // 86400} days, {sec % 86400 // 3600} hours, {(sec % 86400) % 3600 // 60} minutes, {(sec % 86400) % 3600 % 60} seconds"
    elif sec > 3600:
        return f"{sec // 3600} hours, {sec % 3600 // 60} minutes, {sec % 3600 % 60} seconds"
    elif sec > 60:
        return f"{sec // 60} minutes, {sec % 60} seconds"
    else:
        return f"{sec} seconds"


from datetime import datetime, timedelta


def get_last_thursday_at_9am():
    now = datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    days_since_thursday = (today.weekday() - 3) % 7
    if days_since_thursday == 0 and now.hour >= 9:
        delta_days = 0
    else:
        delta_days = days_since_thursday
    last_thursday = today - timedelta(days=delta_days)
    return last_thursday.replace(hour=9, minute=0, second=0, microsecond=0)


import socket


def resolve_ip(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "? (rserr)"


def hist_pct(b):
    return b.get('pkt') or b.get('pct') or b.get('percent') or b.get('count') or 0


import requests, json
import configparser
import os

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

BUZZ_URL = config.get('BUZZ_API', 'BUZZ_URL')
BUZZ_REPLY_URL = config.get('BUZZ_API', 'BUZZ_REPLY_URL')

def send_notification(token, chat_id, text, respond_to = None):
    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
    }
    
    if respond_to:
        payload = {
            "source_sync_id": respond_to,
            "reply": {
                "status": "ok",
                "body": text,
            },
            "opts": {},
        }
        resp = requests.post(BUZZ_REPLY_URL, headers=headers, data=json.dumps(payload), timeout=10)
        resp.raise_for_status()
        return resp.json()
    
    payload = {
        "group_chat_id": chat_id,
        "notification": {
            "status": "ok",
            "body": text,
        },
        "opts": {}
    }
    resp = requests.post(url=BUZZ_URL, headers=headers, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    return resp.json()
