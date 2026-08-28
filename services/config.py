"""Centralized config access for alert_center.

All other modules should read configuration values through the accessor
functions exposed here instead of re-implementing the configparser boilerplate.

The file is parsed exactly once (memoized). Importing this module is cheap
and triggers no I/O beyond the (cached) file read.
"""

import configparser
import functools
import os

CONFIG_FILENAME = 'alert_center.conf'


@functools.lru_cache(maxsize=1)
def _config():
    cfg = configparser.ConfigParser()
    here = os.path.dirname(os.path.abspath(__file__))
    current = here
    while True:
        candidate = os.path.join(current, CONFIG_FILENAME)
        if os.path.isfile(candidate):
            cfg.read(candidate)
            return cfg
        parent = os.path.dirname(current)
        if parent == current:
            cfg.read(os.path.join(here, '..', CONFIG_FILENAME))
            return cfg
        current = parent


def _get(section, key, fallback=None):
    cfg = _config()
    if fallback is not None:
        return cfg.get(section, key, fallback=fallback)
    return cfg.get(section, key)


def _getint(section, key, fallback=None):
    cfg = _config()
    if fallback is not None:
        return cfg.getint(section, key, fallback=fallback)
    return cfg.getint(section, key)


# --- DATABASE_PATHS --------------------------------------------------------

def alerts_db_path():
    return _get('DATABASE_PATHS', 'ALERTS_DB_PATH')


def kuma_status_db_path():
    return _get('DATABASE_PATHS', 'KUMA_STATUS_DB_PATH')


def mitigations_db_path():
    return _get('DATABASE_PATHS', 'MITIGATIONS_DB_PATH')


def current_mitigations_pkl_path():
    return _get('DATABASE_PATHS', 'CURRENT_MITIGATIONS_PKL_PATH')


# --- CLICKHOUSE -------------------------------------------------------------

def clickhouse_host():
    return _get('CLICKHOUSE', 'HOST')


def clickhouse_port():
    return _getint('CLICKHOUSE', 'PORT')


def clickhouse_user():
    return _get('CLICKHOUSE', 'USER')


def clickhouse_database():
    return _get('CLICKHOUSE', 'DATABASE')


# --- OPENSEARCH -------------------------------------------------------------

def opensearch_host():
    return _get('OPENSEARCH', 'HOST')


def opensearch_port():
    return _getint('OPENSEARCH', 'PORT')


def opensearch_username():
    return _get('OPENSEARCH', 'USERNAME')


def opensearch_password():
    return _get('OPENSEARCH', 'PASSWORD')


# --- BUZZ_API --------------------------------------------------------------

def buzz_url():
    return _get('BUZZ_API', 'BUZZ_URL')


def buzz_reply_url():
    return _get('BUZZ_API', 'BUZZ_REPLY_URL')


def alert_center_bot_id():
    return _get('BUZZ_API', 'ALERT_CENTER_BOT_ID')


def alert_center_bot_key():
    return _get('BUZZ_API', 'ALERT_CENTER_BOT_KEY')


def alert_center_bot_token():
    return _get('BUZZ_API', 'ALERT_CENTER_BOT_TOKEN')


def alert_center_chat_id():
    return _get('BUZZ_API', 'ALERT_CENTER_CHAT_ID')


def csirt_bot_token():
    return _get('BUZZ_API', 'CSIRT_BOT_TOKEN')


def csirt_chat_id():
    return _get('BUZZ_API', 'CSIRT_CHAT_ID')


def mitigations_bot_token():
    return _get('BUZZ_API', 'MITIGATIONS_BOT_TOKEN')


def mitigations_chat_id():
    return _get('BUZZ_API', 'MITIGATIONS_CHAT_ID')


def kuma_bot_id():
    return _get('BUZZ_API', 'KUMA_BOT_ID')


def kuma_bot_key():
    return _get('BUZZ_API', 'KUMA_BOT_KEY')


def kuma_bot_token():
    return _get('BUZZ_API', 'KUMA_BOT_TOKEN')


def kuma_bot_chat_id():
    return _get('BUZZ_API', 'KUMA_BOT_CHAT_ID')


def genie_info_chat_id():
    return _get('BUZZ_API', 'GENIE_INFO_CHAT_ID')


def buzz_b2b_chat_id():
    return _get('BUZZ_API', 'BUZZ_B2B_CHAT_ID')


def test_chat_id():
    return _get('BUZZ_API', 'TEST_CHAT_ID')


# --- NSPA_BOT --------------------------------------------------------------

def nspa_chat_id():
    return _get('NSPA_BOT', 'NSPA_CHAT_ID')


def test_nspa_chat_id():
    return _get('NSPA_BOT', 'TEST_NSPA_CHAT_ID')


def notify_chat_id():
    return _get('NSPA_BOT', 'NOTIFY_CHAT_ID')


def nspa_team_user_ids():
    raw = _get('NSPA_BOT', 'NSPA_TEAM_USER_IDS', fallback='')
    return [uid.strip() for uid in raw.split(',') if uid.strip()]


def nspa_bot_port():
    return _getint('NSPA_BOT', 'NSPA_BOT_PORT', fallback=6002)


# --- OIDC -------------------------------------------------------------------

def oidc_issuer_url():
    return _get('OIDC', 'ISSUER_URL', fallback='https://idphydra-uat.beeline.ru')


def oidc_client_id():
    return _get('OIDC', 'CLIENT_ID', fallback='8912f179-f485-4088-a494-bf342ae3638a')


def oidc_client_secret():
    return _get('OIDC', 'CLIENT_SECRET', fallback='OZy0DYs.35TUEeKNg7PBVG_Y86')


def oidc_client_name():
    return _get('OIDC', 'CLIENT_NAME', fallback='Alert Center')


# --- AI_API -----------------------------------------------------------------

def ai_api_url():
    return _get('AI_API', 'URL')


def ai_api_key():
    return _get('AI_API', 'KEY')


def ai_model():
    return _get('AI_API', 'MODEL')

