import os
import re
import sys
import time
import json
import datetime as _dt
from zoneinfo import ZoneInfo
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notifyavr.log")


def _log_call(person: str) -> None:
    ts = _dt.datetime.now(MSK).isoformat(timespec="seconds")
    with open(_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"call+sms to {person} at {ts}\n")


BASE_URL = "https://stos.vimpelcom.ru/Notifyavr/api"
TOKEN = "65e8c3165014a3a54ab1d6b4c9cbcc4fe7f82e4557e2aaaa"

DEFAULT_TEXT = "Вам звонит бот виртуальной смены. Пришло сообщение от НСПА, которое требует вашего внимания.  \
Вам звонит бот виртуальной смены. Пришло сообщение от НСПА, которое требует вашего внимания."

ADDOS_TEAM = {
    1: ('dnmonakhov@beeline.ru', '+7 967 008-25-07'), # Дима
    2: ('avorobevpotupchik@beeline.ru', '+7 968 079-90-80'), # Андрей
    3: ('izaznobin@yaroslavl.beeline.ru','+7 961 027-03-38'), # Илья
    #4: ('askashaev@yaroslavl.beeline.ru','+7 961 023-23-28'), # Леша
    5: ('ilukyantsev@beeline.ru','+7 926 641-60-83'), # Ваня
    6: ('oksvitsmirnova@yaroslavl.beeline.ru','+7 906 634-69-41'), # Оксана
    7: ('seraushakov@yaroslavl.beeline.ru','+7 906 636-82-73'), # Сережа
    8: ('nshemyakin@yaroslavl.beeline.ru','+7 960 533-47-79'), # Никита
    
    10: ('LVelueta@beeline.ru', '+7 (969) 069-45-62') # Лео
}


MSK = ZoneInfo("Europe/Moscow")

# Hardcoded August 2026 duty schedule.
# Weekday shifts: 9:00 -> 09:00 next day --Weekday shifts: 18:00 -> 09:00 next day--.
# Weekend shifts: 09:00 -> 09:00 next day.
# Tuples: (start_dt, end_dt, member_id), all MSK.
DUTY_SCHEDULE = [
    (_dt.datetime(2026, 8, 18, 9, 0), _dt.datetime(2026, 8, 19, 9, 0), 7),  # Сережа Wed
    (_dt.datetime(2026, 8, 19, 9, 0), _dt.datetime(2026, 8, 20, 9, 0), 2),  # Андрей Wed
    (_dt.datetime(2026, 8, 20, 9, 0), _dt.datetime(2026, 8, 21, 9, 0), 3),  # Илья   Thu
    (_dt.datetime(2026, 8, 21, 9, 0), _dt.datetime(2026, 8, 22, 9, 0), 8),  # Никита Fri
    (_dt.datetime(2026, 8, 22, 9, 0),  _dt.datetime(2026, 8, 23, 9, 0), 5),  # Ваня   Sat
    (_dt.datetime(2026, 8, 23, 9, 0),  _dt.datetime(2026, 8, 24, 9, 0), 2),  # Андрей Sun
    (_dt.datetime(2026, 8, 24, 9, 0), _dt.datetime(2026, 8, 25, 9, 0), 3),  # Илья   Mon
    (_dt.datetime(2026, 8, 25, 9, 0), _dt.datetime(2026, 8, 26, 9, 0), 6),  # Оксана Tue
    (_dt.datetime(2026, 8, 26, 9, 0), _dt.datetime(2026, 8, 27, 9, 0), 8),  # Никита Wed
    (_dt.datetime(2026, 8, 27, 9, 0), _dt.datetime(2026, 8, 28, 9, 0), 5),  # Ваня   Thu
    (_dt.datetime(2026, 8, 28, 9, 0), _dt.datetime(2026, 8, 29, 9, 0), 2),  # Андрей Fri
    (_dt.datetime(2026, 8, 29, 9, 0),  _dt.datetime(2026, 8, 30, 9, 0), 3),  # Илья   Sat
    (_dt.datetime(2026, 8, 30, 9, 0),  _dt.datetime(2026, 8, 31, 9, 0), 6),  # Оксана Sun
    (_dt.datetime(2026, 8, 31, 9, 0), _dt.datetime(2026, 9, 1, 9, 0), 5),   # Ваня   Mon
]


def get_on_duty_member_id() -> int:
    now = _dt.datetime.now(MSK)
    for start, end, mid in DUTY_SCHEDULE:
        if start.replace(tzinfo=MSK) <= now < end.replace(tzinfo=MSK):
            return mid
    return 10  # Leo fallback outside scheduled window


def normalize_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("8"):
        digits = "7" + digits[1:]
    elif not digits.startswith("7"):
        digits = "7" + digits
    return digits


def _print_request(method, url, headers, body=None):
    print("\n========== REQUEST ==========")
    print(f"{method} {url}")
    print("Headers:")
    for k, v in headers.items():
        if k.lower() == "authorization":
            print(f"  {k}: Bearer <TOKEN>")
        else:
            print(f"  {k}: {v}")
    if body is not None:
        print("Body:")
        print(json.dumps(body, ensure_ascii=False, indent=2))


def _print_response(resp):
    print("\n========== RESPONSE ==========")
    print(f"HTTP {resp.status_code} {resp.reason}")
    print("Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    print("Body:")
    try:
        print(json.dumps(resp.json(), ensure_ascii=False, indent=2))
    except ValueError:
        print(resp.text)


def send_notify(
    text: str,
    phone: str | None = None,
    users=None,
    channels=None,
    tts_voice: str = "xenia", 
    speed: float = 1.0,
    kol_call: str = "3",
    pause: str = "1",
    wait_time: str = "45",
    verbose: bool = False,
    user_phones: dict | None = None,
):
    if channels is None:
        channels = ["VOICE"]

    if user_phones is None and phone is None:
        raise ValueError("send_notify requires either `phone` or `user_phones`.")

    payload = {
        "text": text,
        "extra_contacts": [],
        "channels": channels,
        "tts_voice": tts_voice,
        "speed": speed,
        "kol_call": kol_call,
        "pause": pause,
        "wait_time": wait_time,
    }

    if user_phones is not None:
        normalized_map = {}
        for u, phones in user_phones.items():
            if isinstance(phones, str):
                phones = [phones]
            normalized_map[u] = [normalize_phone(p) for p in phones]
        payload["users"] = list(user_phones.keys())
        payload["user_phones"] = normalized_map
    elif users:
        normalized_phone = normalize_phone(phone)
        payload["users"] = list(users)
        payload["user_phones"] = {u: [normalized_phone] for u in users}

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
    }

    if verbose:
        _print_request("POST", f"{BASE_URL}/notify", headers, payload)

    resp = requests.post(
        f"{BASE_URL}/notify",
        headers=headers,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        timeout=30,
        verify=False,
    )

    if verbose:
        _print_response(resp)

    resp.raise_for_status()
    return resp.json()


def notify_team(
    text: str = DEFAULT_TEXT,
    ids: list | None = None,
    channels=None,
    tts_voice: str = "xenia",
    speed: float = 1.0,
    kol_call: str = "3",
    pause: str = "1",
    wait_time: str = "45",
    verbose: bool = False,
):
    if ids is None:
        ids = list(ADDOS_TEAM.keys())

    user_phones = {}
    for i in ids:
        entry = ADDOS_TEAM.get(i)
        if entry is None:
            print(f"[warn] ADDOS_TEAM id {i} not found, skipping.")
            continue
        email, phone = entry
        user_phones[email] = [phone]

    if not user_phones:
        raise ValueError("No valid ADDOS_TEAM members selected; user_phones is empty.")

    print(
        f"Notifying {len(user_phones)} ADDOS_TEAM member(s): "
        + ", ".join(user_phones.keys())
    )

    return send_notify(
        text=text,
        user_phones=user_phones,
        channels=channels,
        tts_voice=tts_voice,
        speed=speed,
        kol_call=kol_call,
        pause=pause,
        wait_time=wait_time,
        verbose=verbose,
    )


def get_status(number_notify: str, verbose: bool = False):
    headers = {"Authorization": f"Bearer {TOKEN}"}

    if verbose:
        _print_request("GET", f"{BASE_URL}/status/{number_notify}", headers)

    resp = requests.get(
        f"{BASE_URL}/status/{number_notify}",
        headers=headers,
        timeout=30,
        verify=False,
    )

    if verbose:
        _print_response(resp)

    if resp.status_code == 404:
        return {
            "error": "404 Not Found",
            "detail": f"No status record for number_notify={number_notify} (notify may have been blocked/not queued).",
        }
    resp.raise_for_status()
    return resp.json()


def list_voices(verbose: bool = False):
    headers = {"Authorization": f"Bearer {TOKEN}"}

    if verbose:
        _print_request("GET", f"{BASE_URL}/voices", headers)

    resp = requests.get(f"{BASE_URL}/voices", headers=headers, timeout=30, verify=False)

    if verbose:
        _print_response(resp)

    resp.raise_for_status()
    return resp.json()




def notify_on_duty_team():
    on_duty_id = get_on_duty_member_id()
    current_on_duty_ids = [on_duty_id]

    member = ADDOS_TEAM.get(on_duty_id, ("unknown", "unknown"))
    now_msk = _dt.datetime.now(MSK).isoformat(timespec="minutes")
    print(f"[duty] on-call member: id={on_duty_id} ({member[0]}) at {now_msk} MSK")

    _log_call(member[0])


    notify_team(
        ids=current_on_duty_ids,
        text="Пришло сообщение от НСПА, которое требует вашего внимания",
        verbose=False,
        channels=["SMS"]
    )
    
    result = notify_team(
        ids=current_on_duty_ids,
        text=DEFAULT_TEXT,
        verbose=False,
        speed=1.0
        #tts_voice='aidar', # random
    )


    number_notify = result.get("number_notify")
    status_value = result.get("status")

    if number_notify and status_value not in ("blocked",):
        print(f"\nWaiting 5s before checking status for {number_notify} ...")
        time.sleep(5)
        get_status(number_notify, verbose=False)
    else:
        print("\nSkipping status check (notify was blocked or no number_notify returned).")




if __name__ == "__main__":
    print("Sending VOICE notify to on-duty ADDOS_TEAM members ...")


    notify_on_duty_team()
