import os
import configparser
import sqlite3
from datetime import datetime, timedelta

import clickhouse_connect
from dash import Dash, html, dcc, callback_context
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
from flask import Response, request
from flask_login import current_user


# --------------------------------------------------------------------------- #
# Config / clients
# --------------------------------------------------------------------------- #
_config = configparser.ConfigParser()
_config.read(os.path.join(os.path.dirname(__file__), '..', '..', 'alert_center.conf'))

CLICKHOUSE_HOST = _config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = _config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = _config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = _config.get('CLICKHOUSE', 'DATABASE')
ALERTS_DB_PATH = _config.get('DATABASE_PATHS', 'ALERTS_DB_PATH')

clickhouse_client = clickhouse_connect.get_client(
    host=CLICKHOUSE_HOST,
    port=CLICKHOUSE_PORT,
    user=CLICKHOUSE_USER,
    database=CLICKHOUSE_DATABASE,
)


# Field types tracked by the manual counter widget (delta-based).
FIELD_MANUAL_HANDLED = 'manual_handled'
FIELD_MANUAL_DEBRIEF = 'manual_debrief'
FIELD_DUMMY = 'dummy'
FIELD_TYPES = [FIELD_MANUAL_HANDLED, FIELD_MANUAL_DEBRIEF, FIELD_DUMMY]


# --------------------------------------------------------------------------- #
# Metric constants — absolute-value fields edited via the Constants card.
# Each is persisted as a row in metrics_manual_log with an absolute `value`
# (NOT a delta). Reading uses _get_value_as_of(field, end_str) which returns
# the latest row with ts <= end_str, or None (renders as '?') when none.
# --------------------------------------------------------------------------- #
FIELD_CONST_CRITICAL_TOTAL         = 'const_critical_services_total'
FIELD_CONST_SERVICES_MONITORING    = 'const_services_with_monitoring'
FIELD_CONST_SERVICES_BASELINE      = 'const_services_with_baseline'
FIELD_CONST_EXERCISES_LEVEL        = 'const_exercises_level'

# Hardcoded network bandwidth (bps) used by the capacity/headroom widget.
BANDWIDTH_BPS = 480_000_000_000  # 480 Gbps

# Ordered list of (field_type, label, min, max) used to build the Constants
# card and to drive the unified callback. min/max are validation bounds; for
# unbounded fields use min=0, max=None.
CONST_FIELDS = [
    (FIELD_CONST_CRITICAL_TOTAL,         'Общее число критичных сервисов',          0, None),
    (FIELD_CONST_SERVICES_MONITORING,    'Число сервисов с активным мониторингом',   0, None),
    (FIELD_CONST_SERVICES_BASELINE,      'Сервисы с актуальным baseline',            0, None),
    (FIELD_CONST_EXERCISES_LEVEL,        'Регулярность учений (1..5)',                1, 5),
]

# Map field_type -> short slug used in element IDs (metrics-const-<slug>-*).
_CONST_SLUGS = {
    FIELD_CONST_CRITICAL_TOTAL:         'critical-total',
    FIELD_CONST_SERVICES_MONITORING:    'services-monitoring',
    FIELD_CONST_SERVICES_BASELINE:      'services-baseline',
    FIELD_CONST_EXERCISES_LEVEL:        'exercises-level',
}

# Default exercises level used only when nothing has been set yet in DB.
EXERCISES_LEVEL_DEFAULT = 3

# Регулярность учений и тестов — scale labels.
EXERCISES_SCALE = [
    (1, 'учения не проводятся'),
    (2, 'нерегулярно, реже 1 раза в год'),
    (3, '1–2 раза в год'),
    (4, 'ежеквартально'),
    (5, 'ежемесячно / плюс tabletop и технические drills'),
]


def _ensure_metrics_log_table():
    """Create the manual-counter log table if it does not already exist.

    Idempotent; safe to call at import time.
    """
    clickhouse_client.command('''
        CREATE TABLE IF NOT EXISTS alert_center.metrics_manual_log (
            ts        DateTime('Europe/Moscow'),
            field_type LowCardinality(String),
            value     UInt64,
            actor     String
        )
        ENGINE = MergeTree()
        ORDER BY (field_type, ts)
    ''')


_ensure_metrics_log_table()


# --------------------------------------------------------------------------- #
# ClickHouse helpers (manual counter widget)
# --------------------------------------------------------------------------- #
def _get_latest_value(field_type):
    """Return the latest cumulative value recorded for field_type, or 0."""
    rows = clickhouse_client.query(
        f"SELECT value FROM metrics_manual_log "
        f"WHERE field_type = '{field_type}' "
        f"ORDER BY ts DESC LIMIT 1"
    ).result_rows
    if rows:
        return int(rows[0][0])
    return 0


def _get_count_in_range(field_type, start_str, end_str):
    """Return the net delta applied to `field_type` within [start_str, end_str].

    Because each log row stores a cumulative `value`, the net delta over the
    period equals (last value recorded in the period) minus (last value
    recorded strictly before the period started). Result is clamped at 0 and
    is 0 when no edits fall inside the period.
    """
    in_period = clickhouse_client.query(
        f"SELECT value FROM metrics_manual_log "
        f"WHERE field_type = '{field_type}' "
        f"AND ts >= toDateTime('{start_str}') "
        f"AND ts <= toDateTime('{end_str}') "
        f"ORDER BY ts DESC LIMIT 1"
    ).result_rows
    if not in_period:
        return 0
    last_in_period = int(in_period[0][0])
    before = clickhouse_client.query(
        f"SELECT value FROM metrics_manual_log "
        f"WHERE field_type = '{field_type}' "
        f"AND ts < toDateTime('{start_str}') "
        f"ORDER BY ts DESC LIMIT 1"
    ).result_rows
    last_before = int(before[0][0]) if before else 0
    return max(0, last_in_period - last_before)


def _get_value_as_of(field_type, end_str):
    """Return the latest absolute `value` for field_type with ts <= end_str.

    Used for Constants fields: each row stores an absolute value (not a
    delta), so the value "as of" any moment is simply the newest row at
    or before that moment. Returns None when no row exists yet (so the
    UI renders '?'). Never returns 0-by-default — that is the whole
    point of the Constants semantics.
    """
    rows = clickhouse_client.query(
        f"SELECT value FROM metrics_manual_log "
        f"WHERE field_type = '{field_type}' "
        f"AND ts <= toDateTime('{end_str}') "
        f"ORDER BY ts DESC LIMIT 1"
    ).result_rows
    if rows:
        return int(rows[0][0])
    return None


def _set_constant_value(field_type, new_value, actor):
    """Append a new row storing an absolute `value` (NOT a delta) for the
    given Constants field. Returns the stored value. Caller is
    responsible for clamping/validation; this function trusts the input.
    """
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    clickhouse_client.command(
        f"INSERT INTO metrics_manual_log "
        f"(ts, field_type, value, actor) VALUES "
        f"(toDateTime('{now_str}'), '{field_type}', {int(new_value)}, '{actor}')"
    )
    return int(new_value)


def _get_recent_actions(field_type, start_str=None, end_str=None, limit=5,
                        is_constant=False):
    """Return the most recent `limit` log rows for field_type as a list of
    dicts: [{'actor': str, 'ts': str, 'change': str, 'value': int}, ...].
    Most recent first.

    When `start_str` and `end_str` are supplied (YYYY-MM-DD HH:MM:SS),
    the query is restricted to that period; the oldest visible row's
    delta is computed against the latest row strictly before the period
    start (or '+1' fallback when no such row exists).

    `change` is the delta THIS row represents (the increment from the
    previous/older row to this row's value). Rows come back DESC, so the
    older row for entry `i` is `rows[i+1]`.

    When `is_constant=True`, the synthetic '+1' fallback for the oldest
    visible row (when no prior baseline exists) is replaced by the
    absolute value formatted as '+N', since Constants fields store
    absolute values rather than +1 increments.
    """
    if start_str and end_str:
        period_clause = (
            f"AND ts >= toDateTime('{start_str}') "
            f"AND ts <= toDateTime('{end_str}')"
        )
    else:
        period_clause = ""
    rows = clickhouse_client.query(
        f"SELECT actor, ts, value FROM metrics_manual_log "
        f"WHERE field_type = '{field_type}' {period_clause} "
        f"ORDER BY ts DESC LIMIT {int(limit)}"
    ).result_rows
    # Compute the "before period" baseline so the oldest visible row gets a
    # real delta instead of the synthetic '+1' fallback when possible.
    baseline_value = None
    if start_str and end_str:
        before = clickhouse_client.query(
            f"SELECT value FROM metrics_manual_log "
            f"WHERE field_type = '{field_type}' "
            f"AND ts < toDateTime('{start_str}') "
            f"ORDER BY ts DESC LIMIT 1"
        ).result_rows
        baseline_value = int(before[0][0]) if before else None
    actions = []
    for i, (actor, ts, value) in enumerate(rows):
        if i + 1 < len(rows):
            older_value = int(rows[i + 1][2])
            delta = int(value) - older_value
            change = f"+{delta}" if delta > 0 else str(delta)
        elif baseline_value is not None:
            delta = int(value) - baseline_value
            change = f"+{delta}" if delta > 0 else str(delta)
        elif is_constant:
            # Constants: no prior row → delta is the whole value.
            v = int(value)
            change = f"+{v}" if v > 0 else str(v)
        else:
            change = '+1'
        actions.append({
            'actor': str(actor) if actor else 'unknown',
            'ts': ts.strftime('%Y-%m-%d %H:%M:%S') if hasattr(ts, 'strftime') else str(ts),
            'change': change,
            'value': int(value),
        })
    return actions


def _render_recent_actions(actions):
    """Render the recent actions list as kv-rows.

    Row order: actor (name) — ts (time) — change, so the time sits right
    next to the name rather than on the far side of the change badge.
    """
    if not actions:
        return html.Div('No actions yet', className='kv-value',
                        style={'color': 'var(--text-muted)', 'fontSize': '12px'})
    items = []
    for a in actions:
        items.append(html.Div([
            html.Span(a['actor'], className='kv-key',
                      style={'flex': '1 1 auto', 'overflow': 'hidden',
                             'textOverflow': 'ellipsis', 'whiteSpace': 'nowrap'}),
            html.Span(a['ts'], className='kv-value',
                      style={'margin': '0 6px', 'color': 'var(--text-muted)',
                             'fontSize': '11px', 'whiteSpace': 'nowrap'}),
            html.Span(a['change'], className='kv-value',
                      style={'color': 'var(--accent, #0d6efd)',
                             'fontWeight': 'bold', 'minWidth': '30px', 'textAlign': 'right'}),
        ], className='kv-row', style={'display': 'flex', 'alignItems': 'center',
                                       'gap': '4px', 'padding': '2px 0'}))
    return html.Div(items)


def _apply_delta(field_type, delta, actor):
    """Append a new row with value = latest + delta (clamped at 0) and
    return the new value. delta must be an int (typically +1 or -1)."""
    latest = _get_latest_value(field_type)
    new_value = max(0, latest + delta)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    clickhouse_client.command(
        f"INSERT INTO metrics_manual_log "
        f"(ts, field_type, value, actor) VALUES "
        f"(toDateTime('{now_str}'), '{field_type}', {new_value}, '{actor}')"
    )
    return new_value


def _increment_field(field_type, actor):
    """Append a new row with value = latest + 1 and return the new value."""
    return _apply_delta(field_type, 1, actor)


def _decrement_field(field_type, actor):
    """Append a new row with value = latest - 1 (clamped at 0)."""
    return _apply_delta(field_type, -1, actor)


def _get_current_actor():
    """Best-effort identifier for the logged-in user."""
    try:
        if current_user.is_authenticated:
            return current_user.username or 'unknown'
    except Exception:
        pass
    return 'unknown'


# --------------------------------------------------------------------------- #
# ClickHouse helper (genie events count widget)
# --------------------------------------------------------------------------- #
# Dedup predicate required because genie_events uses ReplacingMergeTree:
# without it duplicates inflate the count until OPTIMIZE TABLE ... FINAL.
_UNIQUE_ID_CONDITION = '''
(ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
)
'''


def _count_genie_events(start_str, end_str):
    """Count distinct Genie events whose START_TIME falls in
    [start_str, end_str]. Returns int.

    start_str / end_str must be in 'YYYY-MM-DD HH:MM:SS' format.
    """
    query = (
        f"SELECT COUNT(*) FROM genie_events "
        f"WHERE START_TIME >= toDateTime('{start_str}') "
        f"AND START_TIME <= toDateTime('{end_str}') "
        f"AND MAX_BPS >= 1000000000 "
        f"AND {_UNIQUE_ID_CONDITION}"
    )
    return int(clickhouse_client.query(query).result_rows[0][0])


def _max_bps_in_period(start_str, end_str):
    """Return the largest MAX_BPS among Genie events whose START_TIME
    falls in [start_str, end_str]. No lower-bound filter is applied —
    every event is considered regardless of size. Returns None when no
    events match (so the widget renders '?').

    start_str / end_str must be in 'YYYY-MM-DD HH:MM:SS' format.
    """
    query = (
        f"SELECT MAX(MAX_BPS) FROM genie_events "
        f"WHERE START_TIME >= toDateTime('{start_str}') "
        f"AND START_TIME <= toDateTime('{end_str}') "
        f"AND {_UNIQUE_ID_CONDITION}"
    )
    rows = clickhouse_client.query(query).result_rows
    if rows and rows[0][0] is not None:
        return int(rows[0][0])
    return None


# --------------------------------------------------------------------------- #
# SQLite helper (alerts-count widget)
# --------------------------------------------------------------------------- #
def _count_level_1_2_alerts(start_str, end_str):
    """Count alerts whose START_TIME falls in [start_str, end_str] and
    LEVEL IN (1, 2). Returns dict {'1': int, '2': int}.

    start_str / end_str must be in 'YYYY-MM-DD HH:MM:SS' format
    (matching the START_TIME TEXT column).
    """
    counts = {'1': 0, '2': 0}
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.execute('PRAGMA busy_timeout = 10000')
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT LEVEL, COUNT(*) FROM alerts "
            "WHERE START_TIME >= ? AND START_TIME <= ? AND LEVEL IN (1, 2) "
            "GROUP BY LEVEL",
            (start_str, end_str),
        )
        for level, n in cursor.fetchall():
            counts[str(int(level))] = int(n)
    finally:
        conn.close()
    return counts


# --------------------------------------------------------------------------- #
# Centralized metrics values (single source of truth for all widgets)
# --------------------------------------------------------------------------- #
def _fmt(v):
    """Render a value as '?' when unknown (None), else as a string."""
    return '?' if v is None else str(v)


def _pct(num, den):
    """Render the answer for a num/den percentage formula.

    Returns '= X.X%' when both num and den are not None and den != 0,
    otherwise '= ?' (matches the existing unknown placeholder style).
    """
    if num is None or den is None or den == 0:
        return '= ?'
    return f"= {num / den * 100:.1f}%"


def _get_metrics_values(start_str, end_str):
    """Return a dict with every number the left-column widgets need.

    Single source of truth: every widget callback reads from here, so
    adding/changing a data source only requires editing this function
    (and the constants block above). Unknowns are returned as None and
    rendered as '?' by _fmt().

    Parameters
    ----------
    start_str, end_str : str
        'YYYY-MM-DD HH:MM:SS' bounds taken from the time-range store.
    """
    level_counts = _count_level_1_2_alerts(start_str, end_str)
    try:
        manual_handled = _get_count_in_range(FIELD_MANUAL_HANDLED, start_str, end_str)
    except Exception:
        manual_handled = 0

    try:
        manual_debrief = _get_count_in_range(FIELD_MANUAL_DEBRIEF, start_str, end_str)
    except Exception:
        manual_debrief = 0

    # "Атаки, выявленные автоматически" = number of Genie events whose
    # START_TIME falls inside the selected period.
    try:
        auto_detected = _count_genie_events(start_str, end_str)
    except Exception:
        auto_detected = None

    # "Все подтвержденные атаки" = Level 1 & 2 alerts in the period.
    confirmed_attacks = level_counts['1'] + level_counts['2']

    # Largest alert bandwidth in the period (None when no events).
    try:
        max_bps = _max_bps_in_period(start_str, end_str)
    except Exception:
        max_bps = None

    # Constants fields are absolute values: read the latest row with
    # ts <= end_str. None (→ '?') when nothing has been set yet.
    try:
        critical_total = _get_value_as_of(FIELD_CONST_CRITICAL_TOTAL, end_str)
    except Exception:
        critical_total = None
    try:
        services_monitored = _get_value_as_of(FIELD_CONST_SERVICES_MONITORING, end_str)
    except Exception:
        services_monitored = None
    try:
        services_baseline = _get_value_as_of(FIELD_CONST_SERVICES_BASELINE, end_str)
    except Exception:
        services_baseline = None
    # Exercises level falls back to the hardcoded default before any edit.
    try:
        exercises_level = _get_value_as_of(FIELD_CONST_EXERCISES_LEVEL, end_str)
    except Exception:
        exercises_level = None
    if exercises_level is None:
        exercises_level = EXERCISES_LEVEL_DEFAULT

    return {
        # Widget 1 — coverage
        'services_monitored':    services_monitored,
        'critical_total':        critical_total,
        # Widget 2 — auto-detected attacks:
        #   numerator   = Genie events in the period
        #   denominator = Level 1 alerts in the period (все подтвержденные атаки)
        'genie_events':          auto_detected,
        'level_1_2_alerts':     level_counts['1'] + level_counts['2'],
        'confirmed_attacks':     confirmed_attacks,
        # Widget 3 — attacks mitigated without business impact
        #   numerator   = confirmed_attacks - manual_debrief
        #   denominator = confirmed_attacks
        'attacks_no_degradation': confirmed_attacks - manual_debrief,
        'manual_debrief':        manual_debrief,
        # Widget 4 — manual intervention
        'manual_handled':        manual_handled,
        # Widget 5 — capacity / headroom = max_bps / 480 Gbps
        'max_bps':               max_bps,
        # Widget 6 — baseline coverage
        'services_with_baseline': services_baseline,
        # Widget 7 — postmortem / PIR
        #   numerator   = manual_debrief (Инциденты, завершенные дебрифом)
        #   denominator = confirmed_attacks (lvl 1 & 2 alerts)
        # (see manual_debrief / confirmed_attacks above)
        # Widget 8 — exercises (constant)
        'exercises_level':       exercises_level,
    }


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #
def _this_month_range():
    now = datetime.now().replace(microsecond=0)
    start = now.replace(day=1, hour=0, minute=0, second=0)
    return start, now


def metrics_time_controls():
    st, en = _this_month_range()
    start_def = st.strftime('%Y-%m-%dT%H:%M:%S')
    end_def = en.strftime('%Y-%m-%dT%H:%M:%S')
    return html.Div([
        html.Div([
            html.Div([
                html.Button('This month', id='metrics-time-q-month', className='btn btn-outline'),
                html.Button('Last 1h',  id='metrics-time-q-1h',   className='btn btn-outline'),
                html.Button('Last 24h', id='metrics-time-q-24h',  className='btn btn-outline'),
                html.Button('Last 7d',  id='metrics-time-q-7d',    className='btn btn-outline'),
                dcc.Input(id='metrics-time-start', type='datetime-local', value=start_def,
                          step=1, style={'width': '200px'}),
                dcc.Input(id='metrics-time-end', type='datetime-local', value=end_def,
                          step=1, style={'width': '200px'}),
                html.Button('Use range', id='metrics-time-update', className='btn btn-outline'),
                html.A('Export PDF', id='metrics-export-pdf', className='btn btn-outline',
                       target='_blank', href='#', style={'marginLeft': '8px'}),
            ], className='time-controls', style={'marginBottom': '0'}),
            dcc.Store(id='metrics-time-range'),
        ], className='card-section-body'),
    ], className='card-section mb-3')


def metrics_resolve_time(ctx):
    if not ctx.triggered:
        st, en = _this_month_range()
        return st, en
    tr = ctx.triggered[0]['prop_id'].split('.')[0]
    now = datetime.now().replace(microsecond=0)
    if tr == 'metrics-time-q-month':
        return _this_month_range()
    if tr == 'metrics-time-q-1h':
        return now - timedelta(hours=1), now
    if tr == 'metrics-time-q-24h':
        return now - timedelta(hours=24), now
    if tr == 'metrics-time-q-7d':
        return now - timedelta(days=7), now
    return None, None


# Maps quick-button IDs to a "relative_kind" stored alongside the time range
# so counter clicks can re-anchor the same period to "now".
TRIGGER_TO_KIND = {
    'metrics-time-q-month': 'month',
    'metrics-time-q-1h': '1h',
    'metrics-time-q-24h': '24h',
    'metrics-time-q-7d': '7d',
}
COUNTER_TRIGGERS = {
    'metrics-manual-btn', 'metrics-manual-dec-btn',
    'metrics-dummy-btn', 'metrics-dummy-dec-btn',
    'metrics-debrief-btn', 'metrics-debrief-dec-btn',
}
# Add the Set buttons for every Constants field so clicking one re-anchors
# the relative time window to "now" (same UX as the +/- counters).
COUNTER_TRIGGERS |= {
    f'metrics-const-{_CONST_SLUGS[ft]}-btn' for ft, _l, _mn, _mx in CONST_FIELDS
}


def _range_for_kind(kind):
    """Return (start, end) for a relative_kind, anchored at the current moment."""
    now = datetime.now().replace(microsecond=0)
    if kind == '1h':
        return now - timedelta(hours=1), now
    if kind == '24h':
        return now - timedelta(hours=24), now
    if kind == '7d':
        return now - timedelta(days=7), now
    return _this_month_range()


# --------------------------------------------------------------------------- #
# Widget builders (left column)
# --------------------------------------------------------------------------- #
def _metric_widget(widget_id, title, formula):
    """Standard metric card: title header, formula subtitle, value placeholder."""
    return html.Div([
        html.Div([html.H4(title)], className='card-section-header'),
        html.Div([
            html.Div(formula, className='kv-value',
                    style={'fontSize': '12px', 'color': 'var(--text-muted)',
                           'marginBottom': '6px'}),
            dcc.Loading([html.Div(id=widget_id, className='kv-value',
                                  style={'fontSize': '18px', 'fontWeight': 'bold'})],
                        type='dot'),
        ], className='card-section-body'),
    ], className='card-section mb-3')


def _exercises_widget():
    """Widget 8: render the 1..5 scale as a numbered list with the
    current selection highlighted. Initial render uses the default;
    the kpi callback overwrites it with the DB-backed value."""
    items = []
    for lvl, label in EXERCISES_SCALE:
        is_selected = (lvl == EXERCISES_LEVEL_DEFAULT)
        items.append(html.Div([
            html.Span(f"{lvl}.", style={
                'display': 'inline-block', 'width': '24px',
                'fontWeight': 'bold' if is_selected else 'normal',
            }),
            html.Span(label, style={
                'fontWeight': 'bold' if is_selected else 'normal',
                'color': 'var(--accent, #0d6efd)' if is_selected else 'inherit',
            }),
            html.Span(' ✓', style={'color': 'var(--accent, #0d6efd)',
                                   'marginLeft': '6px'}) if is_selected else None,
        ], style={'padding': '2px 0', 'fontSize': '12px'}))
    return html.Div([
        html.Div([html.H4('Регулярность учений и тестов')], className='card-section-header'),
        html.Div([
            html.Div(items, id='metrics-w-exercises',
                     style={'marginTop': '4px'}),
        ], className='card-section-body'),
    ], className='card-section mb-3')


def _constants_card():
    """Right-column card holding one editable row per Constants field.

    Each row mirrors the +/- counter layout: label + large value + input
    + Set button on the left, recent-actions log on the right. Element
    IDs follow `metrics-const-<slug>-{value,input,btn,recent}` so the
    unified callback can address them.
    """
    rows = []
    for field_type, label, min_v, max_v in CONST_FIELDS:
        slug = _CONST_SLUGS[field_type]
        input_props = {
            'id': f'metrics-const-{slug}-input',
            'type': 'number',
            'min': min_v,
            'placeholder': 'new value',
            'style': {'width': '110px'},
        }
        if max_v is not None:
            input_props['max'] = max_v
        rows.append(html.Div([
            html.Div(label, className='section-subtitle'),
            dbc.Row([
                dbc.Col([
                    html.Div('?', id=f'metrics-const-{slug}-value',
                             style={'fontSize': '28px', 'fontWeight': 'bold'}),
                    html.Div([
                        dcc.Input(**input_props),
                        html.Button('Set', id=f'metrics-const-{slug}-btn',
                                    className='btn btn-outline', n_clicks=0,
                                    style={'marginLeft': '4px'}),
                    ], style={'marginTop': '4px', 'display': 'flex',
                              'alignItems': 'center', 'gap': '4px'}),
                ], md=6),
                dbc.Col([
                    html.Div(id=f'metrics-const-{slug}-recent'),
                ], md=6),
            ], className='mb-3'),
        ]))
    return html.Div([
        html.Div([
            html.I(className='bi bi-sliders me-2'),
            html.H4('Constants')
        ], className='card-section-header'),
        html.Div(rows, className='card-section-body'),
    ], className='card-section mb-3')


def metrics_layout():
    return html.Div([
        dcc.Location(id='url'),

        # Time controls: full width on top, applies to every widget below.
        metrics_time_controls(),

        dbc.Row([
            # Left column: alerts widget + 9 KPI widgets
            dbc.Col([
                # Widget 0: Level 1 & 2 alerts count
                html.Div([
                    html.Div([
                        html.I(className='bi bi-bar-chart-fill me-2'),
                        html.H4('Level 1 & 2 alerts')
                    ], className='card-section-header'),
                    html.Div([
                        dcc.Loading([html.Div(id='metrics-alerts-count')], type="dot"),
                    ], className='card-section-body')
                ], className='card-section mb-3'),

                # Widget 1: Покрытие мониторингом защищаемых сервисов
                _metric_widget(
                    'metrics-w-coverage',
                    'Покрытие мониторингом защищаемых сервисов',
                    '(число сервисов с активным мониторингом / общее число критичных сервисов) × 100%'
                ),

                # Widget 2: Доля атак, обнаруженных автоматически
                _metric_widget(
                    'metrics-w-auto-detected',
                    'Доля подверждённых атак из обнаруженных автоматически',
                    '(все подтвержденные атаки / атаки, выявленные автоматически) × 100%'
                ),

                # Widget 3: Доля атак, успешно смягченных без влияния на бизнес
                _metric_widget(
                    'metrics-w-mitigated',
                    'Доля атак, успешно смягченных без влияния на бизнес',
                    '((все подтвержденные атаки − Инциденты, завершенные дебрифом) / все подтвержденные атаки) × 100%'
                ),

                # Widget 4: Доля инцидентов с ручным вмешательством
                _metric_widget(
                    'metrics-w-manual',
                    'Доля инцидентов с ручным вмешательством',
                    '(инциденты с ручным вмешательством / все подтвержденные атаки) × 100%'
                ),

                # Widget 5: Достаточность capacity / headroom
                _metric_widget(
                    'metrics-w-capacity',
                    'Достаточность capacity / headroom',
                    '(max bps of the biggest alert for the period / 480 Gbps) × 100%'
                ),

                # Widget 6: Доля сервисов с заранее определенным профилем нормального трафика
                _metric_widget(
                    'metrics-w-baseline',
                    'Доля сервисов с заранее определенным профилем нормального трафика',
                    '(сервисы с актуальным baseline / все критичные сервисы) × 100%'
                ),

                # Widget 7: Доля инцидентов с postmortem / PIR
                _metric_widget(
                    'metrics-w-postmortem',
                    'Доля инцидентов с postmortem / PIR',
                    '(Инциденты, завершенные дебрифом / lvl 1 & 2 alert) × 100%'
                ),

                # Widget 8: Регулярность учений и тестов (numbered scale, hardcoded selection)
                _exercises_widget(),
            ], md=6),

            # Right column: manual counter widget
            dbc.Col([
                html.Div([
                    html.Div([
                        html.I(className='bi bi-hand-index-thumb me-2'),
                        html.H4('Manual counter')
                    ], className='card-section-header'),
                    html.Div(id='metrics-counter-time-label', className='time-range-label',
                             style={'marginBottom': '8px'}),
                    html.Div([
                        # Manually handled alerts: counter+buttons beside action log
                        html.Div('Инциденты с ручным вмешательством ', className='section-subtitle'),
                        dbc.Row([
                            dbc.Col([
                                html.Div('0', id='metrics-manual-value',
                                         style={'fontSize': '36px', 'fontWeight': 'bold'}),
                                html.Div([
                                    html.Button('+1', id='metrics-manual-btn',
                                                className='btn btn-outline', n_clicks=0),
                                    html.Button('-1', id='metrics-manual-dec-btn',
                                                className='btn btn-outline', n_clicks=0,
                                                style={'marginLeft': '4px'}),
                                ], style={'marginTop': '4px'}),
                            ], md=6),
                            dbc.Col([
                                html.Div(id='metrics-manual-recent'),
                            ], md=6),
                        ], className='mb-3'),

                        # Debrief: counter+buttons beside action log
                        html.Div('Инциденты, завершенные дебрифом', className='section-subtitle'),
                        dbc.Row([
                            dbc.Col([
                                html.Div('0', id='metrics-debrief-value',
                                         style={'fontSize': '36px', 'fontWeight': 'bold'}),
                                html.Div([
                                    html.Button('+1', id='metrics-debrief-btn',
                                                className='btn btn-outline', n_clicks=0),
                                    html.Button('-1', id='metrics-debrief-dec-btn',
                                                className='btn btn-outline', n_clicks=0,
                                                style={'marginLeft': '4px'}),
                                ], style={'marginTop': '4px'}),
                            ], md=6),
                            dbc.Col([
                                html.Div(id='metrics-debrief-recent'),
                            ], md=6),
                        ], className='mb-3'),

                        # Dummy: counter+buttons beside action log
                        html.Div('Dummy', className='section-subtitle'),
                        dbc.Row([
                            dbc.Col([
                                html.Div('0', id='metrics-dummy-value',
                                         style={'fontSize': '36px', 'fontWeight': 'bold'}),
                                html.Div([
                                    html.Button('+1', id='metrics-dummy-btn',
                                                className='btn btn-outline', n_clicks=0),
                                    html.Button('-1', id='metrics-dummy-dec-btn',
                                                className='btn btn-outline', n_clicks=0,
                                                style={'marginLeft': '4px'}),
                                ], style={'marginTop': '4px'}),
                            ], md=6),
                            dbc.Col([
                                html.Div(id='metrics-dummy-recent'),
                            ], md=6),
                        ]),
                    ], className='card-section-body')
                ], className='card-section mb-3'),

                # Constants card: absolute-value editable fields below the
                # +/- counters, in the same right column.
                _constants_card(),
            ], md=6),
        ]),
    ], className='page-container')


# --------------------------------------------------------------------------- #
# Callbacks
# --------------------------------------------------------------------------- #
def register_metrics_callbacks(app):
    # IDs of the 12 Constants "Set" buttons — added as Inputs so that a
    # Set click re-anchors the relative time window (the existing
    # COUNTER_TRIGGERS branch handles the actual re-anchoring logic).
    _const_btn_ids = [f'metrics-const-{_CONST_SLUGS[ft]}-btn'
                      for ft, _l, _mn, _mx in CONST_FIELDS]

    @app.callback(
        Output('metrics-time-range', 'data'),
        Output('metrics-export-pdf', 'href'),
        Input('metrics-time-q-month', 'n_clicks'),
        Input('metrics-time-q-1h', 'n_clicks'),
        Input('metrics-time-q-24h', 'n_clicks'),
        Input('metrics-time-q-7d', 'n_clicks'),
        Input('metrics-time-update', 'n_clicks'),
        Input('metrics-manual-btn', 'n_clicks'),
        Input('metrics-manual-dec-btn', 'n_clicks'),
        Input('metrics-dummy-btn', 'n_clicks'),
        Input('metrics-dummy-dec-btn', 'n_clicks'),
        Input('metrics-debrief-btn', 'n_clicks'),
        Input('metrics-debrief-dec-btn', 'n_clicks'),
        # Constants Set buttons.
        *[Input(_bid, 'n_clicks') for _bid in _const_btn_ids],
        State('metrics-time-start', 'value'),
        State('metrics-time-end', 'value'),
        State('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_metrics_time_range(qm, q1h, q24h, q7d, q_update,
                                 m_inc, m_dec, d_inc, d_dec,
                                 db_inc, db_dec,
                                 *_trailing):
        # _trailing = (N const-button n_clicks, start_text, end_text, prev_range)
        # The const-click values are intentionally unused — only `tr`
        # (derived below from callback_context.triggered) matters for
        # routing; the COUNTER_TRIGGERS branch handles Set-button clicks.
        *_const_clicks, start_text, end_text, prev_range = _trailing
        tr = (callback_context.triggered[0]['prop_id'].split('.')[0]
              if callback_context.triggered else None)
        now = datetime.now().replace(microsecond=0)

        def _parse_dt(text):
            if not text:
                return None
            if 'T' in text:
                text = text.replace('T', ' ')
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
                try:
                    return datetime.strptime(text, fmt)
                except ValueError:
                    continue
            return None

        if tr is None:
            # Initial load → behave like "This month".
            st, en = _this_month_range()
            kind, mode = 'month', 'relative'
        elif tr == 'metrics-time-update':
            st = _parse_dt(start_text) or _this_month_range()[0]
            en = _parse_dt(end_text) or now
            kind, mode = None, 'absolute'
        elif tr in TRIGGER_TO_KIND:
            kind = TRIGGER_TO_KIND[tr]
            st, en = _range_for_kind(kind)
            mode = 'relative'
        elif tr in COUNTER_TRIGGERS:
            # A counter +/- was clicked. Re-anchor the currently selected
            # relative period to "now" so the just-recorded edit lands inside
            # the window and every dependent widget (alerts count, counter
            # value, action log, time label) refreshes accordingly.
            prev = prev_range or {}
            if prev.get('mode') == 'absolute':
                # Counters are disabled in absolute mode; if we somehow get
                # here, keep the stored absolute range unchanged.
                prev_href = (
                    f"{app.get_relative_path('/export-pdf')}"
                    f"?start={prev.get('start_iso', '')}&end={prev.get('end_iso', '')}"
                )
                return prev, prev_href
            kind = prev.get('relative_kind') or 'month'
            st, en = _range_for_kind(kind)
            mode = 'relative'
        else:
            st, en = _this_month_range()
            kind, mode = 'month', 'relative'

        editable = mode == 'relative'
        time_range_data = {
            'mode': mode,
            'editable': editable,
            'relative_kind': kind,
            'start_iso': st.strftime('%Y-%m-%dT%H:%M:%S'),
            'end_iso': en.strftime('%Y-%m-%dT%H:%M:%S'),
            'start_str': st.strftime('%Y-%m-%d %H:%M:%S'),
            'end_str': en.strftime('%Y-%m-%d %H:%M:%S'),
        }
        export_href = (
            f"{app.get_relative_path('/export-pdf')}"
            f"?start={time_range_data['start_iso']}&end={time_range_data['end_iso']}"
        )
        return time_range_data, export_href

    @app.callback(
        Output('metrics-alerts-count', 'children'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_alerts_count(time_range):
        start = time_range['start_str']
        end = time_range['end_str']
        try:
            counts = _count_level_1_2_alerts(start, end)
        except Exception as e:
            return html.Div(f"Error: {e}", className='kv-value')
        total = counts['1'] + counts['2']
        return html.Div([
            html.Div(f"{start}  ->  {end}", className='time-range-label'),
            html.Div(str(total), style={'fontSize': '72px', 'fontWeight': 'bold'}),
            html.Div(
                f"Level 1: {counts['1']}   ·   Level 2: {counts['2']}",
                className='section-subtitle'
            ),
        ])

    @app.callback(
        Output('metrics-counter-time-label', 'children'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_counter_time_label(time_range):
        if not time_range:
            return ''
        return f"{time_range['start_str']}  ->  {time_range['end_str']}"

    @app.callback(
        Output('metrics-manual-btn', 'disabled'),
        Output('metrics-manual-dec-btn', 'disabled'),
        Output('metrics-dummy-btn', 'disabled'),
        Output('metrics-dummy-dec-btn', 'disabled'),
        Output('metrics-debrief-btn', 'disabled'),
        Output('metrics-debrief-dec-btn', 'disabled'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def toggle_counter_buttons(time_range):
        disabled = not (time_range or {}).get('editable', True)
        return disabled, disabled, disabled, disabled, disabled, disabled

    # ------------------------------------------------------------------ #
    # Constants: disable the input+button pairs whenever editing is
    # locked (i.e. the time range is in absolute mode). Same gating as
    # toggle_counter_buttons above.
    # ------------------------------------------------------------------ #
    _const_input_ids = [f'metrics-const-{_CONST_SLUGS[ft]}-input'
                        for ft, _l, _mn, _mx in CONST_FIELDS]
    _const_value_ids = [f'metrics-const-{_CONST_SLUGS[ft]}-value'
                        for ft, _l, _mn, _mx in CONST_FIELDS]
    _const_recent_ids = [f'metrics-const-{_CONST_SLUGS[ft]}-recent'
                         for ft, _l, _mn, _mx in CONST_FIELDS]

    @app.callback(
        *[Output(_cid, 'disabled') for _cid in _const_input_ids],
        *[Output(_bid, 'disabled') for _bid in _const_btn_ids],
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def toggle_const_inputs(time_range):
        disabled = not (time_range or {}).get('editable', True)
        # 2 disabled flags per Constants field (input + button).
        return tuple([disabled] * (len(_const_input_ids) + len(_const_btn_ids)))

    # ------------------------------------------------------------------ #
    # Constants: unified callback that handles all Set buttons and
    # refreshes the value displays + recent-actions logs.
    # ------------------------------------------------------------------ #
    @app.callback(
        *[Output(_vid, 'children') for _vid in _const_value_ids],
        *[Output(_rid, 'children') for _rid in _const_recent_ids],
        *[Input(_bid, 'n_clicks') for _bid in _const_btn_ids],
        Input('metrics-time-range', 'data'),
        *[State(_iid, 'value') for _iid in _const_input_ids],
        prevent_initial_call=False,
    )
    def update_constants(*args):
        # Unpack args: N button n_clicks, 1 time_range, N input values.
        n_btns = args[:len(_const_btn_ids)]
        time_range = args[len(_const_btn_ids)]
        input_vals = args[len(_const_btn_ids) + 1:]

        ctx = callback_context
        triggered_id = (ctx.triggered[0]['prop_id'].split('.')[0]
                        if ctx.triggered else None)
        editable = (time_range or {}).get('editable', True)
        start_str = (time_range or {}).get('start_str')
        end_str = (time_range or {}).get('end_str')

        # If a Set button was clicked, persist the matching input value.
        if triggered_id and triggered_id in _const_btn_ids and editable:
            idx = _const_btn_ids.index(triggered_id)
            field_type, _label, min_v, max_v = CONST_FIELDS[idx]
            raw = input_vals[idx]
            try:
                val = int(raw) if raw is not None else None
            except (TypeError, ValueError):
                val = None
            if val is not None:
                if val < min_v:
                    val = min_v
                if max_v is not None and val > max_v:
                    val = max_v
                actor = _get_current_actor()
                try:
                    _set_constant_value(field_type, val, actor)
                except Exception:
                    pass

        # Refresh every constant's value + recent actions.
        values = []
        recents = []
        for field_type, _label, _mn, _mx in CONST_FIELDS:
            v = None
            if end_str:
                try:
                    v = _get_value_as_of(field_type, end_str)
                except Exception:
                    v = None
            values.append('?' if v is None else str(v))
            try:
                if start_str and end_str:
                    actions = _get_recent_actions(
                        field_type, start_str, end_str, limit=3, is_constant=True)
                else:
                    actions = _get_recent_actions(
                        field_type, limit=3, is_constant=True)
                recents.append(_render_recent_actions(actions))
            except Exception as e:
                recents.append(html.Div(f"Error: {e}", className='kv-value',
                                        style={'color': 'var(--text-muted)',
                                               'fontSize': '12px'}))
        return tuple(values + recents)

    @app.callback(
        Output('metrics-manual-value', 'children'),
        Output('metrics-manual-recent', 'children'),
        Input('metrics-manual-btn', 'n_clicks'),
        Input('metrics-manual-dec-btn', 'n_clicks'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_manual(inc_clicks, dec_clicks, time_range):
        ctx = callback_context
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None
        editable = (time_range or {}).get('editable', True)
        start_str = time_range['start_str'] if time_range else None
        end_str = time_range['end_str'] if time_range else None
        if editable:
            actor = _get_current_actor()
            if triggered_id == 'metrics-manual-btn' and inc_clicks:
                _increment_field(FIELD_MANUAL_HANDLED, actor)
            elif triggered_id == 'metrics-manual-dec-btn' and dec_clicks:
                _decrement_field(FIELD_MANUAL_HANDLED, actor)
        if start_str and end_str:
            new_val = _get_count_in_range(FIELD_MANUAL_HANDLED, start_str, end_str)
            recent = _render_recent_actions(
                _get_recent_actions(FIELD_MANUAL_HANDLED, start_str, end_str, 5))
        else:
            new_val = _get_latest_value(FIELD_MANUAL_HANDLED)
            recent = _render_recent_actions(_get_recent_actions(FIELD_MANUAL_HANDLED, 5))
        return str(new_val), recent

    @app.callback(
        Output('metrics-debrief-value', 'children'),
        Output('metrics-debrief-recent', 'children'),
        Input('metrics-debrief-btn', 'n_clicks'),
        Input('metrics-debrief-dec-btn', 'n_clicks'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_debrief(inc_clicks, dec_clicks, time_range):
        ctx = callback_context
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None
        editable = (time_range or {}).get('editable', True)
        start_str = time_range['start_str'] if time_range else None
        end_str = time_range['end_str'] if time_range else None
        if editable:
            actor = _get_current_actor()
            if triggered_id == 'metrics-debrief-btn' and inc_clicks:
                _increment_field(FIELD_MANUAL_DEBRIEF, actor)
            elif triggered_id == 'metrics-debrief-dec-btn' and dec_clicks:
                _decrement_field(FIELD_MANUAL_DEBRIEF, actor)
        if start_str and end_str:
            new_val = _get_count_in_range(FIELD_MANUAL_DEBRIEF, start_str, end_str)
            recent = _render_recent_actions(
                _get_recent_actions(FIELD_MANUAL_DEBRIEF, start_str, end_str, 5))
        else:
            new_val = _get_latest_value(FIELD_MANUAL_DEBRIEF)
            recent = _render_recent_actions(_get_recent_actions(FIELD_MANUAL_DEBRIEF, 5))
        return str(new_val), recent

    @app.callback(
        Output('metrics-dummy-value', 'children'),
        Output('metrics-dummy-recent', 'children'),
        Input('metrics-dummy-btn', 'n_clicks'),
        Input('metrics-dummy-dec-btn', 'n_clicks'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_dummy(inc_clicks, dec_clicks, time_range):
        ctx = callback_context
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None
        editable = (time_range or {}).get('editable', True)
        start_str = time_range['start_str'] if time_range else None
        end_str = time_range['end_str'] if time_range else None
        if editable:
            actor = _get_current_actor()
            if triggered_id == 'metrics-dummy-btn' and inc_clicks:
                _increment_field(FIELD_DUMMY, actor)
            elif triggered_id == 'metrics-dummy-dec-btn' and dec_clicks:
                _decrement_field(FIELD_DUMMY, actor)
        if start_str and end_str:
            new_val = _get_count_in_range(FIELD_DUMMY, start_str, end_str)
            recent = _render_recent_actions(
                _get_recent_actions(FIELD_DUMMY, start_str, end_str, 5))
        else:
            new_val = _get_latest_value(FIELD_DUMMY)
            recent = _render_recent_actions(_get_recent_actions(FIELD_DUMMY, 5))
        return str(new_val), recent

    # ------------------------------------------------------------------ #
    # Single multi-output callback driving all 8 left-column KPI widgets.
    # Reads from _get_metrics_values() (the centralized source of truth).
    # ------------------------------------------------------------------ #
    @app.callback(
        Output('metrics-w-coverage', 'children'),
        Output('metrics-w-auto-detected', 'children'),
        Output('metrics-w-mitigated', 'children'),
        Output('metrics-w-manual', 'children'),
        Output('metrics-w-capacity', 'children'),
        Output('metrics-w-baseline', 'children'),
        Output('metrics-w-postmortem', 'children'),
        Output('metrics-w-exercises', 'children'),
        Input('metrics-time-range', 'data'),
        prevent_initial_call=False,
    )
    def update_kpi_widgets(time_range):
        if not time_range:
            start_str, end_str = _this_month_range()
            start_str = start_str.strftime('%Y-%m-%d %H:%M:%S')
            end_str = end_str.strftime('%Y-%m-%d %H:%M:%S')
        else:
            start_str = time_range['start_str']
            end_str = time_range['end_str']

        try:
            vals = _get_metrics_values(start_str, end_str)
        except Exception as e:
            err = html.Div(f"Error: {e}", style={'color': 'var(--text-muted)',
                                                 'fontSize': '12px'})
            return [err] * 8

        # Widget 1 — coverage
        coverage = (
            f"({_fmt(vals['services_monitored'])}/{_fmt(vals['critical_total'])}) "
            f"{_pct(vals['services_monitored'], vals['critical_total'])}"
        )
        # Widget 2 — auto-detected attacks
        #   numerator   = Genie events in the period (атаки, выявленные автоматически)
        #   denominator = Level 1 alerts in the period (все подтвержденные атаки)
        #auto = (
        #    f"({_fmt(vals['genie_events'])}/{_fmt(vals['level_1_2_alerts'])}) "
        #    f"{_pct(vals['genie_events'], vals['level_1_2_alerts'])}"
        #)
        auto = (
            f"({_fmt(vals['level_1_2_alerts'])}/{_fmt(vals['genie_events'])}) "
            f"{_pct( vals['level_1_2_alerts'], vals['genie_events'])}"
        )


        # Widget 3 — mitigated without business impact
        #   numerator   = confirmed_attacks - manual_debrief
        #   denominator = confirmed_attacks
        mitigated = (
            f"({_fmt(vals['attacks_no_degradation'])}/{_fmt(vals['confirmed_attacks'])}) "
            f"{_pct(vals['attacks_no_degradation'], vals['confirmed_attacks'])}"
        )
        # Widget 4 — manual intervention
        manual = (
            f"({_fmt(vals['manual_handled'])}/{_fmt(vals['confirmed_attacks'])}) "
            f"{_pct(vals['manual_handled'], vals['confirmed_attacks'])}"
        )
        # Widget 5 — capacity / headroom = max_bps / 480 Gbps
        max_bps = vals['max_bps']
        if max_bps is None:
            capacity = '?'
        else:
            gbps = max_bps / 1_000_000_000
            pct = max_bps / BANDWIDTH_BPS * 100
            capacity = f"({gbps:.1f} Gbps / 480 Gbps) = {pct:.1f}%"
        # Widget 6 — baseline coverage
        baseline = (
            f"({_fmt(vals['services_with_baseline'])}/{_fmt(vals['critical_total'])}) "
            f"{_pct(vals['services_with_baseline'], vals['critical_total'])}"
        )
        # Widget 7 — postmortem / PIR
        #   numerator   = manual_debrief (Инциденты, завершенные дебрифом)
        #   denominator = confirmed_attacks (lvl 1 & 2 alert)
        postmortem = (
            f"({_fmt(vals['manual_debrief'])}/{_fmt(vals['confirmed_attacks'])}) "
            f"{_pct(vals['manual_debrief'], vals['confirmed_attacks'])}"
        )
        # Widget 8 — exercises scale (numbered list with selected level highlighted)
        ex_items = []
        for lvl, label in EXERCISES_SCALE:
            is_selected = (lvl == vals['exercises_level'])
            ex_items.append(html.Div([
                html.Span(f"{lvl}.", style={
                    'display': 'inline-block', 'width': '24px',
                    'fontWeight': 'bold' if is_selected else 'normal',
                }),
                html.Span(label, style={
                    'fontWeight': 'bold' if is_selected else 'normal',
                    'color': 'var(--accent, #0d6efd)' if is_selected else 'inherit',
                }),
                html.Span(' ✓', style={'color': 'var(--accent, #0d6efd)',
                                       'marginLeft': '6px'}) if is_selected else None,
            ], style={'padding': '2px 0', 'fontSize': '12px'}))
        exercises = html.Div(ex_items)

        return (coverage, auto, mitigated, manual, capacity,
                baseline, postmortem, exercises)


def create_metrics_app(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.CYBORG, '/static/styles.css'])
    app.layout = metrics_layout()
    register_metrics_callbacks(app)

    export_route = url_base_pathname + 'export-pdf'

    @server.route(export_route)
    def metrics_export_pdf():
        start = request.args.get('start')
        end = request.args.get('end')
        if not start or not end:
            st, en = _this_month_range()
            start = st.strftime('%Y-%m-%dT%H:%M:%S')
            end = en.strftime('%Y-%m-%dT%H:%M:%S')
        try:
            from alert_center.views.metrics_pdf import build_metrics_pdf
            pdf_bytes = build_metrics_pdf(start, end)
        except Exception as e:
            return Response(f"PDF generation failed: {e}", status=500, mimetype='text/plain')

        filename = (f"metrics_{start.replace(':', '-').replace(' ', '_')}_"
                    f"{end.replace(':', '-').replace(' ', '_')}.pdf")
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    return app

