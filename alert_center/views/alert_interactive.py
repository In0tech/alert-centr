from flask import Blueprint, render_template, request
from dash import Dash, html, dcc, dash_table, callback_context
from dash import dash, dcc, html, callback, Input, Output, dash_table
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import pandas as pd
import ipaddress

from services.data_fetcher import (
    get_alert,
    get_alerts,
    get_related_genie,
    get_dp_data,
    get_dp_drops_timeseries,
    waf_blocks_by_net,
    get_waf_decisions_timeseries,
    get_kuma_status,
    get_kuma_events_by_time,
    get_mitigations,
    get_mitigations_for_cidr,
    get_mitigation_events,
    _MOSCOW_OFFSET_MS,
)
from services.utils import c_rounding, c_compact

import json

import dash_ag_grid as dag
from dash import Dash, html

# Networks whose alerts should be visually highlighted in the alerts table.
# An alert row is highlighted if its target_cidr overlaps (intersects or is
# contained by) any of these networks.
HIGHLIGHT_NETWORKS = [ipaddress.ip_network(c) for c in [
    "37.9.244.0/24",
    "37.9.245.0/24",
    "62.231.7.208/28",
    "85.115.249.0/24",
    "217.118.84.0/24",
    "217.118.85.0/24",
    "217.118.86.0/24",
    "217.118.87.0/24",
    "80.243.79.0/24",
    "80.243.78.0/24",
]]

from alert_center.views.theme import (
    grid_ag_theme,
    genie_columnDefs,
    alerts_columnDefs,
    mitigations_columnDefs,
    mitigations_history_columnDefs,
    STYLE,
    PIE_COLORS,
)

# Local override of alerts_columnDefs: end_time cells holding the
# sentinel '9999-12-31 23:59:59' (substituted for empty end_time in
# load_alerts_data below) are displayed as empty strings so ongoing
# alerts still appear blank to the user, while sorting as a very
# high value.
_alerts_columnDefs_local = [dict(c) for c in alerts_columnDefs]
for _col in _alerts_columnDefs_local:
    if _col.get('field') == 'end_time':
        _col['valueFormatter'] = {"function":
            "(params.value === '9999-12-31 23:59:59' "
            "|| params.value === null || params.value === undefined) "
            "? '' : params.value"
        }

from datetime import datetime, timedelta

import ipaddress
import plotly.graph_objects as go


# -- DP/WAF histogram helpers -------------------------------------------------

# "Nice" OpenSearch fixed_interval candidates (>= 1 minute). Picked smallest
# that is >= raw_seconds so we get ~7 buckets across the whole window.
_NICE_INTERVALS = [
    (60,        '1m'),
    (120,       '2m'),
    (300,       '5m'),
    (600,       '10m'),
    (900,       '15m'),
    (1800,      '30m'),
    (3600,      '1h'),
    (7200,      '2h'),
    (14400,     '4h'),
    (21600,     '6h'),
    (43200,     '12h'),
    (86400,     '1d'),
    (604800,    '7d'),
    (2592000,   '30d'),
]


_INTERVAL_TO_SECS = {label: secs for secs, label in _NICE_INTERVALS}


def _interval_to_ms(interval_str):
    """OpenSearch fixed_interval string (e.g. '1m', '30d') -> milliseconds.

    Used to size DP/WAF histogram bars so each bar's left edge sits on its
    bucket key and its right edge sits one interval later (instead of being
    centered on the key). Hover still shows the original bucket key.
    """
    return _INTERVAL_TO_SECS[interval_str] * 1000


def _compute_histogram_window(start_time, end_time):
    """Compute the (window_start, window_end, alert_start, alert_end, interval)
    tuple for the DP/WAF before/during/after histograms.

    Rules (per spec):
      - alert duration Y = end - start (ongoing -> now - start; no after part).
      - Padding is symmetric: a single "nice" interval (from _NICE_INTERVALS)
        closest to Y/3 is applied on each side of the alert. For ongoing alerts
        the after-side is skipped (window_end stays at `now`) since there is no
        "post-alert" yet and future buckets would be empty.
      - Bucket interval: the "nice" interval whose bucket count is closest to
        30 across the whole window. Targets ~30 buckets for any span.

    Returns datetime objects and an OpenSearch fixed_interval string.
    """
    start = pd.to_datetime(start_time)
    if end_time:
        end = pd.to_datetime(end_time)
        ongoing = False
    else:
        end = pd.to_datetime(datetime.now())
        ongoing = True

    if end < start:
        # Defensive: corrupted alert; fall back to a 5-min symmetric window.
        end = start + timedelta(minutes=5)

    duration = end - start
    duration_secs = duration.total_seconds()

    # Symmetric "nice" padding closest to duration/3. The _NICE_INTERVALS list
    # is sorted ascending by seconds, so the closest entry is the one whose
    # midpoint the target falls in. Picking by absolute distance handles the
    # edge cases (tiny alerts land on the 1m floor; long alerts on 30d) without
    # special-casing.
    pad_target_secs = duration_secs / 3.0
    pad_secs = _NICE_INTERVALS[0][0]
    best_pad_score = None
    for secs, _label in _NICE_INTERVALS:
        if secs <= 0:
            continue
        score = abs(secs - pad_target_secs)
        if best_pad_score is None or score < best_pad_score:
            best_pad_score = score
            pad_secs = secs
    pad = timedelta(seconds=pad_secs)

    window_start = start - pad
    if ongoing:
        window_end = pd.to_datetime(datetime.now())
    else:
        window_end = end + pad

    total_span = (window_end - window_start).total_seconds()
    # Pick the "nice" interval whose bucket count is closest to 30 across the
    # whole window. ~30 buckets keeps short alerts granular and long alerts
    # readable without an overwhelming number of bars.
    interval_str = '30d'
    best_score = None
    for secs, label in _NICE_INTERVALS:
        if secs <= 0:
            continue
        score = abs((total_span / secs) - 30.0)
        if best_score is None or score < best_score:
            best_score = score
            interval_str = label

    return window_start, window_end, start, end, interval_str, ongoing


def _hist_layout_defaults(title, y_title, span_seconds=None, x_range=None):
    """Shared plotly layout for the DP/WAF histograms. Mirrors
    reports_interactive._hist_layout_defaults but lives locally so this view
    stays self-contained.

    When span_seconds is provided the x-axis is treated as a date axis and
    given a tickformat matching the window width so the alert-phase shapes
    (which use datetime x0/x1) line up with the bars.

    When x_range is provided (a (start, end) tuple of datetimes) the x-axis
    range is fixed so Plotly does not autorange to fit shapes — this keeps
    the red alert band from re-extending the visible axis past trimmed data
    on ended alerts."""
    if span_seconds is None:
        tickformat = None
    elif span_seconds <= 3600:
        tickformat = '%m-%d %H:%M:%S'
    elif span_seconds <= 86400:
        tickformat = '%m-%d %H:%M'
    else:
        tickformat = '%m-%d %H:%M'

    xaxis = dict(tickangle=-45, tickfont=dict(size=8))
    if tickformat is not None:
        xaxis['type'] = 'date'
        xaxis['tickformat'] = tickformat
    if x_range is not None:
        xaxis['range'] = [x_range[0], x_range[1]]

    return dict(
        title=title,
        margin=dict(l=40, r=10, t=30, b=60),
        height=260,
        paper_bgcolor=STYLE['chart_paper_bg'],
        plot_bgcolor=STYLE['chart_plot_bg'],
        font=dict(color=STYLE['text_muted'], size=STYLE['chart_font_size']),
        xaxis=xaxis,
        yaxis=dict(title=y_title, gridcolor=STYLE['chart_grid']),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        bargap=0.1,
    )


def _alert_phase_shapes(alert_start, alert_end, ongoing):
    """Build the shaded rectangle + vertical dashed lines marking the alert
    phase on the histogram x-axis."""
    shapes = []
    # Shaded band over the alert window — reddish so it stands out from the
    # blue/cyan bars used for DP drops and WAF Pass/Block.
    band_end = alert_end if not ongoing else pd.to_datetime(datetime.now())
    shapes.append(dict(
        type='rect',
        xref='x', yref='paper',
        x0=alert_start, x1=band_end, y0=0, y1=1,
        fillcolor='#cf222e',
        opacity=0.14,
        line_width=0,
        layer='below',
    ))
    # Vertical dashed line at alert start.
    shapes.append(dict(
        type='line',
        xref='x', yref='paper',
        x0=alert_start, x1=alert_start, y0=0, y1=1,
        line=dict(color=STYLE['accent_orange'], width=1.5, dash='dash'),
    ))
    # Vertical dashed line at alert end (only if it ended).
    if not ongoing:
        shapes.append(dict(
            type='line',
            xref='x', yref='paper',
            x0=alert_end, x1=alert_end, y0=0, y1=1,
            line=dict(color=STYLE['accent_orange'], width=1.5, dash='dash'),
        ))
    return shapes


def alerts_layout():
    return html.Div([
        dcc.Location(id='url'),
        dcc.Store(id='clicked-alert-uid'),
        html.Div(
            [
                html.Span(
                    id='vcit-capacity-text',
                    className='vcit-capacity-text',
                    children='0.00 / 10 Gbps  аномального трафика ВК ИТ',
                ),
                dbc.Switch(
                    id='alerts-autoupdate',
                    value=False,
                    label='Auto-update (30s)',
                    class_name='autoupdate-switch',
                ),
                dcc.Interval(
                    id='alerts-autoupdate-interval',
                    interval=30000,
                    n_intervals=0,
                    disabled=True,
                ),
            ],
            className='vcit-capacity-banner',
        ),
        html.Div([
            html.Div([
                html.I(className='bi bi-bell-fill me-2'),
                html.H4('Live Alerts'),
            ], className='card-section-header'),
            html.Div([
                html.Label(' Голубым выделены алерты ВК ИТ. '),
                html.Label('Уровни алертов: 1 (высокий: ≥10k DP-дропов И ≥1 Гбит/с), 2 (средний: одно из двух), 3 (низкий: ни одного условия или нет оценки)'),
            ], className='card-section-body'),
            html.Div([
                dag.AgGrid(
                    id="alerts-table",
                    columnDefs=_alerts_columnDefs_local,
                    columnSize="sizeToFit",
                    defaultColDef={"filter": "agTextColumnFilter"},
                    dashGridOptions={"enableCellTextSelection": True, "ensureDomOrder": True,
                                      "animateRows": True,
                                      "theme": grid_ag_theme,
                                      "rowClassRules": {
                                          "alert-highlighted":
                                              "params.data && params.data._highlighted"
                                      }},
                )
            ], className='card-section-body')
        ], className='card-section mb-3'),
            
        html.Div([
            html.Div([
                html.I(className='bi bi-shield-fill me-2'),
                html.H4('Live Mitigations')
            ], className='card-section-header'),
            html.Div([
                dag.AgGrid(
                    id="mitigations-table",
                    columnDefs=mitigations_columnDefs,
                    columnSize="sizeToFit",
                    defaultColDef={"filter": "agTextColumnFilter"},
                    dashGridOptions={"enableCellTextSelection": True, "ensureDomOrder": True,
                                      "animateRows": True,
                                      "theme": grid_ag_theme},
                )
            ], className='card-section-body')
        ], className='card-section'),

        html.Div([
            html.Div([
                html.I(className='bi bi-clock-history me-2'),
                html.H4('Mitigation Changes (last 7d)')
            ], className='card-section-header'),
            html.Div([
                dag.AgGrid(
                    id="mitigations-history-table",
                    columnDefs=mitigations_history_columnDefs,
                    columnSize="sizeToFit",
                    defaultColDef={"filter": "agTextColumnFilter"},
                    dashGridOptions={"enableCellTextSelection": True, "ensureDomOrder": True,
                                      "animateRows": True,
                                      "theme": grid_ag_theme},
                )
            ], className='card-section-body')
        ], className='card-section')

    ], className='page-container')


def register_alerts_overview_callbacks(app):
    @app.callback(
        Output('alerts-autoupdate-interval', 'disabled'),
        Input('alerts-autoupdate', 'value'),
    )
    def _toggle_alerts_autoupdate(enabled):
        return not bool(enabled)

    @app.callback(
        Output("alerts-table", "rowData"),
        Output('vcit-capacity-text', 'children'),
        Input('url', 'pathname'),
        Input('alerts-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_alerts_data(pathname, n_intervals):
        print("Loading alerts table data")
        try:
            df = get_alerts()
            df['alert_uid'] = df['alert_uid'].apply(lambda x: f"[{x}](/alert/{x})")
            df['level'] = df['level'].fillna(0).replace(0, 3).astype(int)

            # Per-second block rates for the combined "total (rate/s)" display.
            # Ongoing alerts use now-start so the rate refreshes each autoupdate
            # pass; ended alerts use end-start (frozen, matches locked totals).
            now_ts = pd.Timestamp.now()
            start = pd.to_datetime(df['start_time'], format='mixed')
            end = pd.to_datetime(df['end_time'], format='mixed', errors='coerce')
            duration = (end.fillna(now_ts) - start).dt.total_seconds().clip(lower=1.0)
            df['waf_blocks_per_sec'] = (df['waf_blocks'].fillna(0) / duration).round(2)
            df['dp_blocks_per_sec'] = (df['dp_blocks'].fillna(0) / duration).round(2)

            # Flag rows whose target_cidr intersects any of the highlight
            # networks so the grid can color them via getRowStyle.
            def _intersects_highlight(cidr):
                try:
                    net = ipaddress.ip_network(str(cidr), strict=False)
                except (ValueError, TypeError):
                    return False
                return any(net.overlaps(h) for h in HIGHLIGHT_NETWORKS)
            df['_highlighted'] = df['target_cidr'].apply(_intersects_highlight)

            # VC IT capacity widget: sum current_max_bps over ongoing
            # (END_TIME IS NULL) highlighted alerts. current_max_bps is the
            # live value maintained by update_alerts() and reflects the
            # instantaneous attack load on watched networks.
            ongoing_highlighted = df[df['_highlighted'] & end.isna()]
            capacity_bps = int(
                pd.to_numeric(ongoing_highlighted['current_max_bps'], errors='coerce')
                .fillna(0)
                .sum()
            )
            capacity_gbps = capacity_bps / 1e9
            capacity_text = f"{capacity_gbps:.2f} / 10 Gbps  аномального трафика ВК ИТ"

            # Substitute empty end_time with a high sentinel so the ag-grid
            # default sort places ongoing alerts last (ascending) / first
            # (descending). The column valueFormatter hides the sentinel.
            df.loc[end.isna(), 'end_time'] = '9999-12-31 23:59:59'

            return df.to_dict('records'), capacity_text
        except Exception as e:
            print(f"Error loading alerts: {e}")
            return [], "0.00 / 10 Gbps  аномального трафика ВК ИТ"

    @app.callback(
        Output("mitigations-table", "rowData"),
        Input('url', 'pathname'),
        Input('alerts-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_mitigations_data(pathname, n_intervals):
        print("Loading mitigations data")
        try:
            df = get_mitigations()
            df = df[df['Mitigation'].notna() & (df['Mitigation'].astype(str).str.strip() != '')]
            df['Update time'] = df['Update time'].dt.strftime('%Y-%m-%d %H:%M:%S')
            return df.to_dict('records')
        except Exception as e:
            print(f"Error loading mitigations: {e}")
            return []

    @app.callback(
        Output("mitigations-history-table", "rowData"),
        Input('url', 'pathname'),
        Input('alerts-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_mitigations_history(pathname, n_intervals):
        print("Loading mitigation history")
        try:
            df = get_mitigation_events(days=7)
            return df.to_dict('records')
        except Exception as e:
            print(f"Error loading mitigation history: {e}")
            return []


####### DETAILS #######

        '''html.Div([
            html.I(className='bi bi-exclamation-triangle-fill me-2'),
            html.H3('Alert Details')
        ], className='page-title'),'''
def detail_layout():
    return html.Div([
        dcc.Location(id='url'),
        html.Div(
            [
                dbc.Switch(
                    id='alert-detail-autoupdate',
                    value=False,
                    label='Auto-update (30s)',
                    class_name='autoupdate-switch',
                ),
                dcc.Interval(
                    id='alert-detail-autoupdate-interval',
                    interval=30000,
                    n_intervals=0,
                    disabled=True,
                ),
            ],
        ),

        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div([
                        html.I(className='bi bi-info-circle-fill me-2'),
                        html.H4('Alert Overview')
                    ], className='card-section-header'),
                    
                    dcc.Loading([html.Div([
                        html.Div(id="alert-overview-content", children=[
                            html.Div([html.Span("Alert ID: ", className='detail-field-label'), html.Span(id="alert-id", className='detail-field-value')], className='detail-field'),
                            html.Div([html.Span("Level: ", className='detail-field-label'), html.Span(id="alert-level", className='detail-field-value')], className='detail-field'),
                            html.Div([html.Span("Target CIDR: ", className='detail-field-label'), html.Span(id="alert-cidr", className='detail-field-value')], className='detail-field'),
                            html.Div([html.Span("Start Time: ", className='detail-field-label'), html.Span(id="alert-start", className='detail-field-value')], className='detail-field'),
                            html.Div([html.Span("End Time: ", className='detail-field-label'), html.Span(id="alert-end", className='detail-field-value')], className='detail-field'),
                            html.Div([html.Span("Max BPS: ", className='detail-field-label'), html.Span(id="alert-bps", className='detail-field-value stat-highlight')], className='detail-field'),
                        ])
                    ], className='card-section-body')], type="dot"),
                    
                ], className='card-section')
            ], md=4),
            dbc.Col([
                html.Div([
                    html.Div([
                        html.I(className='bi bi-diagram-3-fill me-2'),
                        html.H4('Related Genie Events')
                    ], className='card-section-header'),
                    
                    dcc.Loading([html.Div([
                        dag.AgGrid(
                            id="genie-events-table",
                            columnDefs=genie_columnDefs,
                            columnSize="sizeToFit",
                            defaultColDef={"filter": "agTextColumnFilter"},
                            dashGridOptions={"enableCellTextSelection": True, "ensureDomOrder": True,
                                              "animateRows": True,
                                              "theme": grid_ag_theme},
                        )
                    ], className='card-section-body')], type="dot"),

                ], className='card-section')
            ], md=8),
        ], className='mb-3'),

        dbc.Row([
            dbc.Col([
                html.Div([
                    html.Div([
                        html.I(className='bi bi-hdd-network-fill me-2'),
                        html.H4('DP (Radware/AntiDDoS) Data')
                    ], className='card-section-header'),
                
                    dcc.Loading([html.Div([
                        html.Div(id="dp-data-output")
                    ], className='card-section-body')], type="dot"),
                
                ], className='card-section')
            ], md=6),
            dbc.Col([
                html.Div([
                    html.Div([
                        html.I(className='bi bi-shield-lock-fill me-2'),
                        html.H4('WAF Data')
                    ], className='card-section-header'),
                
                    dcc.Loading([html.Div([
                        html.Div(id="waf-data-output")
                    ], className='card-section-body')], type="dot"),
                
                ], className='card-section')
            ], md=6),
        ], className='mb-3'),

        html.Div([
            html.Div([
                html.I(className='bi bi-bug-fill me-2'),
                html.H4('Diagnostics')
            ], className='card-section-header'),
            
            dcc.Loading([html.Div([
                html.Pre(id="random-stuff", className='data-pre')
            ], className='card-section-body')], type="dot"),
            
        ], className='card-section'),
    ], className='page-container')


def register_alert_detail_callbacks(app):
    @app.callback(
        Output('alert-detail-autoupdate-interval', 'disabled'),
        Input('alert-detail-autoupdate', 'value'),
    )
    def _toggle_alert_detail_autoupdate(enabled):
        return not bool(enabled)

    @app.callback(
        Output("random-stuff", "children"),
        Input('url', 'pathname'),
        Input('alert-detail-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def test_stuff(pathname, n_intervals):
        alert_id = pathname.split('/')[-1]
        alert: pd.DataFrame = get_alert(alert_id)
        if alert.empty:
            return
        alert = alert.iloc[0]

        # df = get_kuma_status(alert['target_cidr'])
        df = get_kuma_events_by_time(alert['start_time'], alert['end_time'])

        alert_ipnet = ipaddress.IPv4Network(alert['target_cidr'])
        alert_net_int = int(alert_ipnet.network_address)
        alert_bro_int = int(alert_ipnet.broadcast_address)

        df2 = get_mitigations_for_cidr(alert_net_int, alert_bro_int)

        kuma_str = df.to_string(index=False) if not df.empty else "No data"

        if not df2.empty:
            mit_view = df2[['TARGET_CIDR', 'CURRENT_MITIGATION', 'UPDATE_TIME_UNIX']].copy()
            mit_view['UPDATE_TIME'] = pd.to_datetime(mit_view['UPDATE_TIME_UNIX'], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
            mit_view = mit_view.drop(columns=['UPDATE_TIME_UNIX']).rename(columns={
                'TARGET_CIDR': 'Target CIDR',
                'CURRENT_MITIGATION': 'Mitigation',
                'UPDATE_TIME': 'Update Time',
            })
            mit_str = mit_view.to_string(index=False)
        else:
            mit_str = "No data"

        return f"Kuma Status:\n\n{kuma_str}\n\n\nMitigations:\n\n{mit_str}"

    @app.callback(
        Output("genie-events-table", "rowData"),
        Output('alert-id', 'children'),
        Output('alert-level', 'children'),
        Output('alert-cidr', 'children'),
        Output('alert-start', 'children'),
        Output('alert-end', 'children'),
        Output('alert-bps', 'children'),
        Input('url', 'pathname'),
        Input('alert-detail-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_alert_details(pathname, n_intervals):
        alert_id = pathname.split('/')[-1]
        print(f"Loading details for alert {alert_id}")

        alert: pd.DataFrame = get_alert(alert_id)
        if alert.empty:
            return [], "", "", "", "", "", ""

        alert = alert.iloc[0]

        df = get_related_genie(alert['target_cidr'], alert['start_time'], alert['end_time'])

        df['resource'] = df['resource'].apply(lambda x: str(x))

        df['last_update'] = pd.to_datetime(df['last_update']).dt.strftime('%Y-%m-%d %H:%M:%S')

        df['start'] = df['start'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))

        df['end'] = df['end'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, datetime) and len(str(x)) > 5 else '')
        df['target_network'] = df['target_network'].apply(lambda x: str(x))
        df['target_broadcast'] = df['target_broadcast'].apply(lambda x: str(x))
        df['max_pps'] = df['max_pps'].apply(lambda x: x if x else 0)
        df['max_bps'] = df['max_bps'].apply(lambda x: x if x else 0)

        def range_to_cidr(start_ip: str, end_ip: str) -> str:
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            total = int(end) - int(start) + 1
            prefix = 32 - (total.bit_length() - 1)
            net = ipaddress.IPv4Network(f"{start}/{prefix}", strict=False)
            return str(net)
        df['Target CIDR'] = df.apply(lambda row: range_to_cidr(row['target_network'], row['target_broadcast']), axis=1)
        df['Importance'] = 1
        df['Data Source'] = 'Genie'

        genie_data = df.to_dict(orient='records')

        start_time = pd.to_datetime(alert['start_time'], format='mixed').strftime('%Y-%m-%d %H:%M:%S')
        end_time = pd.to_datetime(alert['end_time'], format='mixed').strftime('%Y-%m-%d %H:%M:%S') if alert['end_time'] else "Ongoing"

        bps_value = alert['max_bps'] if alert['end_time'] else (alert['current_max_bps'] or alert['max_bps'])

        return (
            genie_data,
            alert['alert_uid'],
            (alert.get('level') or 3) if not pd.isna(alert.get('level')) else 3,
            alert['target_cidr'],
            start_time,
            end_time,
            c_rounding(bps_value, 'bps'),
        )

    @app.callback(
        Output('dp-data-output', 'children'),
        Input('url', 'pathname'),
        Input('alert-detail-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_dp_data(pathname, n_intervals):
        alert_id = pathname.split('/')[-1]
        print(f"Loading dp data for alert {alert_id}")

        alert: pd.DataFrame = get_alert(alert_id)
        if alert.empty:
            return ""

        alert = alert.iloc[0]

        # --- text totals (alert window only) ---
        try:
            dp_data = get_dp_data(alert['target_cidr'], alert['start_time'], alert['end_time'], top_descriptions_num=10)
        except Exception as e:
            print(f"Error getting dp data: {e}")
            return html.Pre(str(e), className='data-pre')

        if 'aggregations' in dp_data and 'top_drop_descriptions' in dp_data['aggregations']:
            dp_agg = dp_data['aggregations']
        else:
            return html.Pre("No DP data", className='data-pre')

        drops_value = dp_agg['drops']['drop_packets']['value'] or 0
        challenges_value = dp_agg['challenges']['challenge_packets']['value'] or 0
        total_non_forward = int(drops_value) + int(challenges_value)

        drop_buckets = dp_agg.get('top_drop_descriptions', {}).get('by_desc', {}).get('buckets', [])
        challenge_buckets = dp_agg.get('top_challenge_descriptions', {}).get('by_desc', {}).get('buckets', [])

        # Comma-joined set of all policies seen (keys are stored with
        # surrounding double quotes, e.g. '"ns-gldn-net-global"'). Dedup
        # while preserving doc_count-desc order from the agg.
        policy_buckets = dp_agg.get('top_policies', {}).get('buckets', [])
        seen_policies = []
        for pb in policy_buckets:
            key = pb.get('key', '').strip().strip('"').strip()
            if key and key not in seen_policies:
                seen_policies.append(key)
        policy_display = ', '.join(seen_policies) if seen_policies else '(none)'

        # --- two-column top-descriptions Pre blocks ---
        # Drops on the left, challenges on the right. Both columns are sorted
        # by packet count desc (the OS agg already orders by total_packets
        # desc). Counts use compact notation via c_compact so wide ranges
        # stay readable in the narrow card.
        def _format_desc_col(buckets, header):
            if not buckets:
                return f"{header}:\n  (none)"
            items = [(b['key'], int(b.get('total_packets', {}).get('value', 0))) for b in buckets]
            if not items:
                return f"{header}:\n  (none)"
            max_label = max(len(k) for k, _ in items)
            formatted = [(k, c_compact(v)) for k, v in items]
            max_count = max(len(c) for _, c in formatted)
            lines = [f"  {k:<{max_label}}  {c:>{max_count}} pkts" for k, c in formatted]
            return f"{header}:\n" + "\n".join(lines)

        drop_col = _format_desc_col(drop_buckets, "Top drop descriptions")
        challenge_col = _format_desc_col(challenge_buckets, "Top challenge descriptions")

        drop_pre = html.Pre(
            drop_col,
            className='data-pre',
            style={'whiteSpace': 'pre', 'overflowX': 'auto', 'flex': '1 1 0', 'minWidth': '0'},
        )
        challenge_pre = html.Pre(
            challenge_col,
            className='data-pre',
            style={'whiteSpace': 'pre', 'overflowX': 'auto', 'flex': '1 1 0', 'minWidth': '0'},
        )

        # Totals + policies block: kept separate from the two description
        # lists so the side-by-side Pre row only contains the descriptions.
        # Policies uses normal wrapping (whiteSpace: pre-wrap) so long lists
        # wrap inside the card instead of extending it horizontally.
        totals_line = (
            f"{c_compact(int(drops_value))} drops + "
            f"{c_compact(int(challenges_value))} challenges = "
            f"{c_compact(total_non_forward)}"
        )
        totals_pre = html.Pre(
            f"{totals_line}\n"
            f"Policies: {policy_display}",
            className='data-pre',
            style={'whiteSpace': 'pre-wrap', 'wordBreak': 'break-word', 'overflowX': 'auto'},
        )

        text_pre = html.Div([
            totals_pre,
            html.Div(
                [drop_pre, challenge_pre],
                style={'display': 'flex', 'gap': '8px', 'width': '100%'},
            ),
        ])

        # --- histogram (before / during / after) ---
        try:
            window_start, window_end, alert_start, alert_end, interval, ongoing = \
                _compute_histogram_window(alert['start_time'], alert['end_time'])
            ts = get_dp_drops_timeseries(
                alert['target_cidr'],
                window_start.strftime('%Y-%m-%d %H:%M:%S'),
                window_end.strftime('%Y-%m-%d %H:%M:%S'),
                interval=interval,
            )
        except Exception as e:
            print(f"Error getting dp timeseries: {e}")
            return text_pre

        if not ts:
            return text_pre

        x_dt = [pd.to_datetime(b['key'], unit='ms') for b in ts]
        y_vals = [b['packets'] for b in ts]

        # If every bucket is zero there's no real activity to chart — skip
        # the empty graph and keep just the text block.
        if sum(y_vals) == 0:
            return text_pre

        # --- stacked-by-action+reason bars ---
        # For each action present in the window (drop / challenge — omit if
        # its window total is 0), pick top-5 reasons and emit one trace per
        # reason named "<action>: <reason>", plus a synthetic "<action>:
        # Other" trace for the remainder so bars still sum to the action's
        # bucket total. Bars are stacked across actions+reasons so a bucket
        # sums to total non-forward packets (drops + challenges, no forward).
        TOP_N = 5
        # action -> {reason: total_packets}
        action_reason_totals = {}
        # action -> total_packets (window)
        action_totals = {}
        for b in ts:
            for ab in b.get('actions', []):
                a_key = ab['key']
                action_totals[a_key] = action_totals.get(a_key, 0) + ab.get('packets', 0)
                rt = action_reason_totals.setdefault(a_key, {})
                for sb in ab.get('buckets', []):
                    rt[sb['key']] = rt.get(sb['key'], 0) + sb.get('packets', 0)

        # Stable, deterministic action order: drop, challenge, then any
        # others (alphabetical). Actions with zero window total are omitted
        # entirely (cleaner legend when there's only one action present).
        def _action_order(a):
            return ({'drop': 0, 'challenge': 1}.get(a, 2), a)
        active_actions = sorted(
            (a for a in action_totals if action_totals[a] > 0),
            key=_action_order,
        )

        color_map = {}
        palette_pools = {
            'drop': PIE_COLORS,
            'challenge': PIE_COLORS[:-2][::-1],
        }

        traces = []
        for action in active_actions:
            rt = action_reason_totals.get(action, {})
            sorted_reasons = sorted(rt.items(), key=lambda kv: kv[1], reverse=True)
            top_reasons = [k for k, _ in sorted_reasons[:TOP_N]]
            top_packets = sum(v for _, v in sorted_reasons[:TOP_N])
            # Emit an "Other" trace when there are more than TOP_N reasons OR
            # when the top-N reasons don't account for all of the action's
            # packets (e.g. docs with no description.keyword, which produce
            # empty reason buckets but still contribute to action_totals).
            has_other = len(sorted_reasons) > TOP_N or action_totals[action] > top_packets
            ordered = top_reasons + (['Other'] if has_other else [])


            span_seconds = (window_end - window_start).total_seconds()
            bar_width_ms = _interval_to_ms(interval)

            palette = palette_pools.get(action, PIE_COLORS)
            for i, reason in enumerate(ordered):
                label = f"{action}: {reason}"
                if reason == 'Other':
                    color_map[label] = PIE_COLORS[-1]
                else:
                    color_map[label] = palette[i % len(palette)]

                def _val(b, action=action, reason=reason, top_reasons=top_reasons):
                    ab = next((a for a in b.get('actions', []) if a['key'] == action), None)
                    if ab is None:
                        return 0
                    if reason == 'Other':
                        accounted = 0
                        for sb in ab.get('buckets', []):
                            if sb['key'] in top_reasons:
                                accounted += sb.get('packets', 0)
                        return max(0, ab.get('packets', 0) - accounted)
                    for sb in ab.get('buckets', []):
                        if sb['key'] == reason:
                            return sb.get('packets', 0)
                    return 0

                ry = [_val(b) for b in ts]
                if sum(ry) == 0:
                    # Skip traces that are entirely zero (e.g. "Other" with
                    # no remainder) so the legend stays clean.
                    continue
                traces.append(go.Bar(
                    x=x_dt, y=ry,
                    name=label,
                    marker_color=color_map[label],
                    width=bar_width_ms,
                    offset=0,
                    hovertemplate=(
                        f'{label}: %{{y}}<br>'
                        f'Time: %{{x|%Y-%m-%d %H:%M:%S}}<extra></extra>'
                    ),
                ))



        fig = go.Figure(traces) # DP drops over time
        fig.update_layout(_hist_layout_defaults('', 'Packets dropped',
                                                span_seconds=span_seconds,
                                                x_range=(window_start, window_end)))
        fig.update_layout(barmode='stack')
        fig.update_layout(shapes=_alert_phase_shapes(alert_start, alert_end, ongoing))

        graph = dcc.Graph(figure=fig, config={'displayModeBar': False})

        bar_width_label = html.Div(
            f"Bar width: {interval}",
            style={
                'color': STYLE['text_muted'],
                'fontSize': STYLE['chart_font_size'],
                'marginBottom': '4px',
            },
        )

        return html.Div([text_pre, bar_width_label, graph])

    @app.callback(
        Output('waf-data-output', 'children'),
        Input('url', 'pathname'),
        Input('alert-detail-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_waf_data(pathname, n_intervals):
        alert_id = pathname.split('/')[-1]
        print(f"Loading waf data for alert {alert_id}")

        alert: pd.DataFrame = get_alert(alert_id)
        if alert.empty:
            return ""

        alert = alert.iloc[0]

        # --- histogram + totals from timeseries ---
        try:
            window_start, window_end, alert_start, alert_end, interval, ongoing = \
                _compute_histogram_window(alert['start_time'], alert['end_time'])
            ts = get_waf_decisions_timeseries(
                alert['target_cidr'],
                window_start.strftime('%Y-%m-%d %H:%M:%S'),
                window_end.strftime('%Y-%m-%d %H:%M:%S'),
                interval=interval,
            )
        except Exception as e:
            print(f"Error getting waf timeseries: {e}")
            # Fall back to legacy aggregated call so the text block still shows.
            try:
                pass_blocks = waf_blocks_by_net(alert['target_cidr'], alert['start_time'], alert['end_time'], timeout=60)
            except Exception as e2:
                return html.Pre(str(e2), className='data-pre')
            if 'aggregations' in pass_blocks and 'pass_block' in pass_blocks['aggregations']:
                buckets = pass_blocks['aggregations']['pass_block']['buckets']
            else:
                buckets = []
            totals = {b['key']: b['doc_count'] for b in buckets}
            return _build_waf_text_pre(totals)

        if not ts:
            return _build_waf_text_pre({})

        # Aggregate totals over the window for the text block.
        totals = {}
        for b in ts:
            for sb in b['buckets']:
                totals[sb['key']] = totals.get(sb['key'], 0) + sb['doc_count']

        # No real activity across the whole window — keep the "(no activity)"
        # text block and skip the empty graph.
        if not totals or sum(totals.values()) == 0:
            return _build_waf_text_pre(totals)

        text_pre = _build_waf_text_pre(totals)

        x_dt = [pd.to_datetime(b['key'], unit='ms') for b in ts]

        # Build stacked bars for Pass and Block (and any other decisions).
        decisions = list(totals.keys())
        # Deterministic order: Pass first, Block second, then anything else.
        decisions.sort(key=lambda d: ({'Pass': 0, 'Block': 1}.get(d, 2), d))

        color_map = {
            'Pass':  STYLE['accent_green'],
            'Block': STYLE['accent_orange'],
        }
        default_colors = [STYLE['accent_bps'], STYLE['accent_cyan'], STYLE['accent_yellow']]
        color_idx = 0
        traces = []
        for d in decisions:
            color = color_map.get(d)
            if color is None:
                color = default_colors[color_idx % len(default_colors)]
                color_idx += 1
            y_vals = []
            for b in ts:
                v = 0
                for sb in b['buckets']:
                    if sb['key'] == d:
                        v = sb['doc_count']
                        break
                y_vals.append(v)
            traces.append(go.Bar(
                x=x_dt, y=y_vals,
                name=d,
                marker_color=color,
                width=_interval_to_ms(interval),
                offset=0,
                hovertemplate=(
                    f'{d}: %{{y}}<br>'
                    f'Time: %{{x|%Y-%m-%d %H:%M:%S}}<extra></extra>'
                ),
            ))

        span_seconds = (window_end - window_start).total_seconds()

        fig = go.Figure(traces)
        fig.update_layout(_hist_layout_defaults('WAF decisions over time', 'Requests',
                                                span_seconds=span_seconds,
                                                x_range=(window_start, window_end)))
        fig.update_layout(barmode='stack')
        fig.update_layout(shapes=_alert_phase_shapes(alert_start, alert_end, ongoing))

        graph = dcc.Graph(figure=fig, config={'displayModeBar': False})

        bar_width_label = html.Div(
            f"Bar width: {interval}",
            style={
                'color': STYLE['text_muted'],
                'fontSize': STYLE['chart_font_size'],
                'marginBottom': '4px',
            },
        )

        return html.Div([text_pre, bar_width_label, graph])


def _build_waf_text_pre(totals):
    """Format the WAF totals dict into a nicely-aligned Pre block.

    Pass and Block are always shown (defaulting to 0) so the operator can see
    at a glance that no blocks occurred, rather than the line being absent.

    Counts are rendered with compact notation (1.23k / 1.23M / 1.23G) via
    c_compact so large block counts stay readable in the narrow card.
    """
    # Always-on counters: Pass and Block default to 0 so the lines are stable.
    display = {'Pass': 0, 'Block': 0}
    if totals:
        for k, v in totals.items():
            display[k] = display.get(k, 0) + v

    total = sum(display.values())
    # Order: Pass, Block, then the rest (alphabetical for determinism).
    keys = sorted(display.keys(), key=lambda d: ({'Pass': 0, 'Block': 1}.get(d, 2), d))
    formatted = {k: c_compact(display[k]) for k in keys}
    total_fmt = c_compact(total)
    max_label = max(len(k) for k in keys)
    max_count = max(len(formatted[k]) for k in keys)
    lines = [
        f"  {k:<{max_label}}  {formatted[k]:>{max_count}}"
        for k in keys
    ]
    sep_w = max_label + max_count + 4
    text = (
        "WAF decisions in alert window:\n"
        + "\n".join(lines)
        + f"\n  {'-' * sep_w}\n"
        + f"  {'Total':<{max_label}}  {total_fmt:>{max_count}}"
    )
    return html.Pre(text, className='data-pre',
                    style={'whiteSpace': 'pre', 'overflowX': 'auto'})


def create_alerts_table_app(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.CYBORG, '/static/styles.css'],
               external_scripts=['/static/ag_grid_custom_filters.js'])

    app.layout = alerts_layout()
    register_alerts_overview_callbacks(app)

    return app


def create_alert_detail_app(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.CYBORG, '/static/styles.css'],
               external_scripts=['/static/ag_grid_custom_filters.js'])

    app.layout = detail_layout()
    register_alert_detail_callbacks(app)

    return app

