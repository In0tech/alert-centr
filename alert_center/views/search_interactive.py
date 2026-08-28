from flask import Blueprint, render_template, request, Response
from dash import Dash, html, dcc, callback_context
from dash import dash, dcc, html, callback, Input, Output
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
from datetime import datetime, timedelta
import ipaddress
import json
import urllib.request
import urllib.parse
import pandas as pd
import plotly.graph_objects as go

from services.utils import get_last_thursday_at_9am, c_compact
from services.data_fetcher import (
    get_alerts_for_search,
    get_genie_events_for_search,
    get_dp_data,
    get_dp_drops_timeseries,
    waf_blocks_by_net,
    get_waf_decisions_timeseries,
    get_top_attack_sources,
)
from alert_center.views.alert_interactive import (
    _compute_histogram_window,
    _hist_layout_defaults,
    _alert_phase_shapes,
    _build_waf_text_pre,
    _interval_to_ms,
)
from alert_center.views.theme import (
    STYLE,
    grid_ag_theme,
    genie_columnDefs,
    alerts_columnDefs,
    PIE_COLORS,
)
from alert_center.views.search_pdf import build_search_pdf
from alert_center.views.reports_pdf_alt import _fetch_top_source_countries
import dash_ag_grid as dag


# ---- NetFlow extended CIDR info (mirrors flow_display search page) ----------
# Self-contained: no flow_display imports (that project is unreachable here).

FLOW_API_URL = 'http://10.26.38.213:5000/api/v1/extended_cidr_info'
FLOW_API_KEY = 'Hc08jWpFngsUWs2cps4rTD0wHHT9wMOaR_3RBN9Pd7ptjeeeSrOn0G7Y4_Esk6hPmrKf_yptEldv6aeE72EnTQ'
FLOW_API_TOP_N = 10

PROTO_MAP = {
    1: 'ICMP', 4: 'IP-in-IP', 6: 'TCP', 17: 'UDP', 27: 'RDP',
    41: 'IPv6', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 89: 'OSPF', 121: 'SMP',
}


def _bytes_to_string(bytes_):
    units = ["B", "Kb", "Mb", "Gb", "Tb"]
    index = 0
    bytes_int = int(bytes_ or 0)
    while bytes_int >= 1024 and index < len(units) - 1:
        bytes_int /= 1024
        index += 1
    return f"{bytes_int:.2f} {units[index]}"


def _pkts_to_string(pkts_):
    units = ["pkts", "Kpkts", "Mpkts", "Gpkts", "Tpkts"]
    index = 0
    pkts_int = int(pkts_ or 0)
    while pkts_int >= 1000 and index < len(units) - 1:
        pkts_int /= 1000
        index += 1
    return f"{pkts_int:.2f} {units[index]}"


def _proto_to_string(proto):
    try:
        proto_int = int(proto)
    except (TypeError, ValueError):
        return str(proto)
    name = PROTO_MAP.get(proto_int)
    if name:
        return f"{name} ({proto_int})"
    return f"Proto \u2116{proto_int}"


def _tcp_flag_int_to_string(tcp_flags_int):
    try:
        tcp_flags_int = int(tcp_flags_int)
    except (TypeError, ValueError):
        return str(tcp_flags_int)
    flags = []
    if tcp_flags_int & 0x01: flags.append("FIN")
    if tcp_flags_int & 0x02: flags.append("SYN")
    if tcp_flags_int & 0x04: flags.append("RST")
    if tcp_flags_int & 0x08: flags.append("PSH")
    if tcp_flags_int & 0x10: flags.append("ACK")
    if tcp_flags_int & 0x20: flags.append("URG")
    if tcp_flags_int & 0x40: flags.append("ECE")
    if tcp_flags_int & 0x80: flags.append("CWR")
    if not flags:
        return "Null"
    return " ".join(flags)


def _flow_api_call(cidr, start_iso, end_iso, top_n=FLOW_API_TOP_N, url_endpoint=None):
    """GET /api/v1/extended_cidr_info. Returns parsed dict or None on error."""
    params = urllib.parse.urlencode({
        'start_time': start_iso,
        'end_time':   end_iso,
        'cidr':       cidr,
        'top_n':      top_n,
    })
    full = f"{FLOW_API_URL}{url_endpoint}?{params}"
    req = urllib.request.Request(full, headers={
        "Authorization": f"Bearer {FLOW_API_KEY}",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            if resp.status != 200:
                return None
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except Exception as e:
        print(f"[search] flow api error: {e}")
        return None


def flow_api_fetch_as_source(cidr, start_iso, end_iso, top_n=FLOW_API_TOP_N):
    """Return the extended_cidr_info/source endpoint response (flat schema).

    The /source route returns the side block flattened to the top level
    (overview, top_src_ips, ..., timeseries, side='source') — no
    as_source wrapper key.
    """
    data = _flow_api_call(cidr, start_iso, end_iso, top_n=top_n, url_endpoint='/source')
    if not data:
        return None
    return data


def flow_api_fetch_as_destination(cidr, start_iso, end_iso, top_n=FLOW_API_TOP_N):
    """Return the extended_cidr_info/destination endpoint response (flat schema).

    The /destination route returns the side block flattened to the top level
    (overview, top_dst_ips, ..., timeseries, side='destination') — no
    as_destination wrapper key.
    """
    data = _flow_api_call(cidr, start_iso, end_iso, top_n=top_n, url_endpoint='/destination')
    if not data:
        return None
    return data


def _flow_gv(a_val, b_val, fmt=str):
    """A / B / delta row, mirroring flow_display utils._gv."""
    a_val = a_val or 0
    b_val = b_val or 0
    diff = b_val - a_val
    sign = '+' if diff >= 0 else '-'
    return html.Span([
        html.Span(f"A: {fmt(a_val)}", className='group-a'),
        html.Span(f"B: {fmt(b_val)}", className='group-b'),
        html.Span(f"\u0394: {sign}{fmt(abs(diff))}",
                  className='delta-positive' if diff >= 0
                  else 'delta-negative'),
    ], className='flow-gv')


def _flow_toplist(items, key_fmt=None):
    """Render [{value, cnt_a, cnt_b}, ...] as a list of A/B/delta rows."""
    if not items:
        return html.Div('No data', className='kv-value')
    rows = []
    for it in items:
        key = key_fmt(it['value']) if key_fmt else str(it['value'])
        rows.append(html.Div([
            html.Span(f"{key}:", className='kv-key'),
            _flow_gv(it['cnt_a'], it['cnt_b']),
        ], className='kv-row'))
    return html.Div(rows)


def _flow_overview_block(overview):
    return [
        html.Div('Overview', className='section-subtitle'),
        html.Div([
            html.Span('Flows:', className='kv-key'),
            _flow_gv(overview['flows']['a'], overview['flows']['b']),
        ], className='kv-row'),
        html.Div([
            html.Span('Bytes:', className='kv-key'),
            _flow_gv(overview['bytes']['a'], overview['bytes']['b'], _bytes_to_string),
        ], className='kv-row'),
        html.Div([
            html.Span('Pkts:', className='kv-key'),
            _flow_gv(overview['pkts']['a'], overview['pkts']['b'], _pkts_to_string),
        ], className='kv-row'),
    ]


def _flow_stats_block(stats):
    """Render min/max/avg/median for bytes & pkts, A & B."""
    items = []
    for unit, fmt in (('bytes', _bytes_to_string), ('pkts', _pkts_to_string)):
        items.append(html.Div(f'IN_{unit.upper()}', className='section-subtitle'))
        for grp in ('a', 'b'):
            b = stats[unit][grp]
            def _fmt(v):
                return fmt(v) if v is not None else 'N/A'
            items.append(html.Div([
                html.Span(f"{grp.upper()}:", className=f'kv-key group-{grp}'),
                html.Span(
                    f"min:{_fmt(b['min'])} max:{_fmt(b['max'])} "
                    f"avg:{('%.2f' % b['avg']) if b['avg'] is not None else 'N/A'} "
                    f"med:{_fmt(b['median'])}",
                    className=f'kv-value group-{grp}',
                ),
            ], className='kv-row'))
    return html.Div(items)


def _flow_section(title, body):
    return [html.Div(title, className='section-subtitle'), body]


def _flow_empty_fig(title):
    fig = go.Figure()
    fig.update_layout(
        title=title,
        paper_bgcolor=STYLE['chart_paper_bg'],
        plot_bgcolor=STYLE['chart_plot_bg'],
        font=dict(color=STYLE['text_main']),
        annotations=[dict(text="No data", showarrow=False,
                          font=dict(color=STYLE['text_muted']))],
        margin=dict(l=40, r=40, t=30, b=40),
    )
    return fig


def _flow_timeseries_fig(points, bucket, title):
    """4 traces: bytes A/B (bars, left y) + pkts A/B (lines, right y).
    Mirrors flow_display data_fetcher._add_timeseries_traces.
    """
    if not points:
        return _flow_empty_fig(title)

    # Shift x by half a bucket so bars/lines sit at the middle of the interval,
    # matching the original search page (data_fetcher.py:184).
    half_delta = timedelta(minutes=30) if bucket == 'minute' else timedelta(minutes=30)
    xs = []
    for p in points:
        try:
            t = datetime.strptime(p['t'][:19], '%Y-%m-%dT%H:%M:%S')
        except (ValueError, TypeError):
            try:
                t = datetime.strptime(p['t'][:19], '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                t = None
        xs.append((t + half_delta) if t else p['t'])

    bytes_a = [p['bytes_a'] for p in points]
    bytes_b = [p['bytes_b'] for p in points]
    pkts_a  = [p['pkts_a']  for p in points]
    pkts_b  = [p['pkts_b']  for p in points]

    fig = go.Figure()
    fig.add_trace(go.Bar(x=xs, y=bytes_a, name='bytes (A)',
                         marker_color=STYLE.get('accent_blue', '#4FC3F7')))
    fig.add_trace(go.Bar(x=xs, y=bytes_b, name='bytes (B)',
                         marker_color=STYLE.get('accent_orange', '#FF8A65')))
    fig.add_trace(go.Scatter(x=xs, y=pkts_a, name='pkts (A)', mode='lines',
                             line=dict(color=STYLE.get('accent_light_blue', '#81D4FA')),
                             yaxis='y2'))
    fig.add_trace(go.Scatter(x=xs, y=pkts_b, name='pkts (B)', mode='lines',
                             line=dict(color=STYLE.get('accent_light_orange', '#FFAB91')),
                             yaxis='y2'))
    fig.update_layout(
        title=title,
        paper_bgcolor=STYLE['chart_paper_bg'],
        plot_bgcolor=STYLE['chart_plot_bg'],
        font=dict(color=STYLE['text_main'], size=10),
        barmode='group',
        yaxis=dict(title='bytes', gridcolor=STYLE.get('border_color', '#3a3f4b')),
        yaxis2=dict(overlaying='y', side='right', title='pkts',
                    gridcolor=STYLE.get('border_color', '#3a3f4b')),
        margin=dict(l=40, r=40, t=30, b=40),
        legend=dict(font=dict(color=STYLE['text_main'], size=10)),
    )
    return fig


SEARCH_WIDGET_KEYS = ['alerts', 'genie', 'dp', 'waf', 'sources', 'flow_src', 'flow_dst']


def _ag_grid(id_, column_defs):
    return dag.AgGrid(
        id=id_,
        columnDefs=column_defs,
        columnSize="sizeToFit",
        defaultColDef={"filter": "agTextColumnFilter"},
        dashGridOptions={"enableCellTextSelection": True, "ensureDomOrder": True,
                          "animateRows": True,
                          "theme": grid_ag_theme},
    )


def _card(header_icon, header_text, body, extra_class=''):
    return html.Div([
        html.Div([
            html.I(className=f'bi bi-{header_icon} me-2'),
            html.H4(header_text)
        ], className='card-section-header'),
        html.Div(body, className='card-section-body')
    ], className=f'card-section mb-3 {extra_class}'.strip())


def search_controls():
    en = get_last_thursday_at_9am()
    st = en - timedelta(days=7)
    start_def = st.strftime('%Y-%m-%dT%H:%M:%S')
    end_def = en.strftime('%Y-%m-%dT%H:%M:%S')
    return html.Div([
        html.Div([
            html.Div([
                dcc.Input(id='search-cidr', type='text', value='',
                          placeholder='CIDR, e.g. 10.0.0.0/24',
                          style={'width': '260px'}),
                dcc.Input(id='search-time-start', type='datetime-local', value=start_def,
                          step=1, style={'width': '200px'}),
                dcc.Input(id='search-time-end', type='datetime-local', value=end_def,
                          step=1, style={'width': '200px'}),
                html.Button('Search', id='search-run', className='btn btn-outline'),
                dcc.Dropdown(
                    id='search-widget-selector',
                    options=[
                        {'label': 'Alerts',             'value': 'alerts'},
                        {'label': 'Related Genie Events','value': 'genie'},
                        {'label': 'DP (Radware/AntiDDoS)','value': 'dp'},
                        {'label': 'WAF',                'value': 'waf'},
                        {'label': 'Top Attack Sources', 'value': 'sources'},
                        {'label': 'NetFlow: CIDR as source',      'value': 'flow_src'},
                        {'label': 'NetFlow: CIDR as destination', 'value': 'flow_dst'},
                    ],
                    value=['alerts', 'genie', 'dp', 'waf', 'sources', 'flow_src', 'flow_dst'],
                    multi=True,
                    placeholder='Widgets…',
                    className='search-widget-dropdown',
                    optionHeight=35,
                ),
                html.A('Export PDF', id='search-export-pdf', className='btn btn-outline',
                       target='_blank', href='#'),
                dbc.Switch(id='search-autoupdate', value=False, label='Auto-update (30s)',
                           class_name='autoupdate-switch'),
                dcc.Interval(id='search-autoupdate-interval', interval=30000, n_intervals=0, disabled=True),
            ], className='time-controls', style={'marginBottom': '0'}),
            dcc.Store(id='search-params'),
        ], className='card-section-body'),
    ], className='card-section mb-3')


def search_layout():
    return html.Div([
        dcc.Location(id='url'),

        search_controls(),

        html.Div(id='search-error',
                 style={'color': STYLE['accent_yellow'], 'marginBottom': '8px'}),

        html.Div([
            _card('bell-fill', 'Alerts', [
                html.Div(id='search-alerts-time-label', className='time-range-label'),
                dcc.Loading([_ag_grid('search-alerts-table', alerts_columnDefs)], type="dot"),
            ]),
        ], id='search-widget-alerts'),

        html.Div([
            _card('diagram-3-fill', 'Related Genie Events', [
                html.Div(id='search-genie-time-label', className='time-range-label'),
                dcc.Loading([_ag_grid('search-genie-table', genie_columnDefs)], type="dot"),
            ]),
        ], id='search-widget-genie'),

        dbc.Row([
            dbc.Col([
                html.Div([
                    _card('hdd-network-fill', 'DP (Radware/AntiDDoS) Data', [
                        html.Div(id='search-dp-time-label', className='time-range-label'),
                        dcc.Loading([html.Div(id='search-dp-output')], type="dot"),
                    ]),
                ], id='search-widget-dp'),
            ], md=6),
            dbc.Col([
                html.Div([
                    _card('shield-lock-fill', 'WAF Data', [
                        html.Div(id='search-waf-time-label', className='time-range-label'),
                        dcc.Loading([html.Div(id='search-waf-output')], type="dot"),
                    ]),
                ], id='search-widget-waf'),
            ], md=6),
        ], className='mb-3'),

        html.Div([
            _card('pie-chart-fill', 'Top Attack Sources', [
                html.Div(id='search-sources-time-label', className='time-range-label'),
                dcc.Loading([
                    dbc.Row([
                        dbc.Col([
                            dcc.Graph(id='search-sources-ip-pie',
                                      config={'displayModeBar': False}),
                        ], md=6),
                        dbc.Col([
                            dcc.Graph(id='search-sources-country-pie',
                                      config={'displayModeBar': False}),
                        ], md=6),
                    ], className='wide-widget-row'),
                ], type="dot"),
            ], extra_class='wide-widget'),
        ], id='search-widget-sources'),

        html.Div([
            _card('download', 'NetFlow: CIDR as source', [
                html.Div(id='search-flow_src-time-label', className='time-range-label'),
                dcc.Loading([
                    dbc.Row([
                        dbc.Col([html.Div(id='search-flow-src-left')],  md=6),
                        dbc.Col([html.Div(id='search-flow-src-right')], md=6),
                    ], className='wide-widget-row'),
                    dcc.Graph(id='search-flow-src-graph',
                              config={'displayModeBar': False}),
                ], type="dot"),
            ], extra_class='wide-widget flow-widget'),
        ], id='search-widget-flow_src'),

        html.Div([
            _card('upload', 'NetFlow: CIDR as destination', [
                html.Div(id='search-flow_dst-time-label', className='time-range-label'),
                dcc.Loading([
                    dbc.Row([
                        dbc.Col([html.Div(id='search-flow-dst-left')],  md=6),
                        dbc.Col([html.Div(id='search-flow-dst-right')], md=6),
                    ], className='wide-widget-row'),
                    dcc.Graph(id='search-flow-dst-graph',
                              config={'displayModeBar': False}),
                ], type="dot"),
            ], extra_class='wide-widget flow-widget'),
        ], id='search-widget-flow_dst'),
    ], className='page-container')


def _parse_params(params):
    """Returns (cidr, start_str, end_str, submitted) or None on invalid CIDR.
    Caller distinguishes 'no submission' from 'invalid' via the submitted flag.
    """
    params = params or {}
    cidr = (params.get('cidr') or '').strip()
    start = params.get('start_str', '')
    end = params.get('end_str', '')
    submitted = bool(params.get('submitted'))
    return cidr, start, end, submitted


def _parse_flow_params(params):
    """Like _parse_params but returns ISO timestamps (what the flow API expects)."""
    params = params or {}
    cidr = (params.get('cidr') or '').strip()
    start_iso = params.get('start_iso', '')
    end_iso = params.get('end_iso', '')
    submitted = bool(params.get('submitted'))
    return cidr, start_iso, end_iso, submitted


def _parse_dt(text):
    """Parse a datetime-local string into a datetime.

    Browser may omit seconds (e.g. 'YYYY-MM-DD HH:MM') when they are :00,
    so try both formats before falling back. Mirrors reports_interactive.py.
    """
    if not text:
        return None
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _validate_cidr(cidr):
    """Returns the IPv4Network or raises ValueError."""
    return ipaddress.IPv4Network(cidr, strict=False)


_PIE_COLORS = PIE_COLORS


def _pie_fig(labels, values, title):
    """Plotly pie figure mirroring reports_pdf_alt._build_pie_drawing's
    percent-label logic. Returns an empty 'No data' figure when there is
    no positive data. Font colors are set explicitly because the CYBORG
    dark theme makes Plotly inherit white text (invisible on white
    paper_bgcolor)."""
    dark = STYLE['text_main']
    muted = STYLE['text_muted']
    if not values or sum(values) == 0:
        fig = go.Figure()
        fig.update_layout(
            title=title,
            paper_bgcolor=STYLE['chart_paper_bg'],
            plot_bgcolor=STYLE['chart_plot_bg'],
            font=dict(color=dark),
            annotations=[dict(text="No data", showarrow=False,
                              font=dict(color=muted))],
            margin=dict(l=20, r=20, t=40, b=20),
        )
        return fig
    colors = [_PIE_COLORS[i % len(_PIE_COLORS)] for i in range(len(labels))]
    fig = go.Figure([go.Pie(
        labels=labels,
        values=values,
        textinfo='percent',
        marker=dict(colors=colors),
        hole=0,
    )])
    fig.update_layout(
        title=title,
        paper_bgcolor=STYLE['chart_paper_bg'],
        plot_bgcolor=STYLE['chart_plot_bg'],
        font=dict(color=dark),
        margin=dict(l=20, r=20, t=40, b=20),
        showlegend=True,
        legend=dict(font=dict(color=dark, size=10)),
    )
    fig.update_traces(textfont=dict(color=dark))
    return fig


def register_search_callbacks(app):
    @app.callback(
        Output('search-autoupdate-interval', 'disabled'),
        Input('search-autoupdate', 'value'),
    )
    def _toggle_search_autoupdate(enabled):
        return not bool(enabled)

    @app.callback(
        [Output(f'search-widget-{k}', 'style') for k in SEARCH_WIDGET_KEYS],
        Input('search-widget-selector', 'value'),
        prevent_initial_call=False
    )
    def toggle_search_widgets(selected):
        selected = selected or []
        return [{'display': 'block' if k in selected else 'none'} for k in SEARCH_WIDGET_KEYS]

    @app.callback(
        Output('search-export-pdf', 'href'),
        Input('search-params', 'data'),
        Input('search-widget-selector', 'value'),
        prevent_initial_call=False
    )
    def update_search_export_href(params, widgets):
        params = params or {}
        start_iso = params.get('start_iso', '')
        end_iso = params.get('end_iso', '')
        cidr = (params.get('cidr') or '').strip()
        widgets_param = ','.join(widgets or [])
        qs = f"start={start_iso}&end={end_iso}&widgets={widgets_param}"
        if cidr:
            qs += f"&cidr={cidr}"
        return app.get_relative_path('/export-pdf') + '?' + qs


    @app.callback(
        Output('search-params', 'data'),
        Input('search-run', 'n_clicks'),
        State('search-cidr', 'value'),
        State('search-time-start', 'value'),
        State('search-time-end', 'value'),
        prevent_initial_call=False
    )
    def update_search_params(n_clicks, cidr, start_text, end_text):
        cidr = (cidr or '').strip()
        if start_text and 'T' in start_text:
            start_text = start_text.replace('T', ' ')
        if end_text and 'T' in end_text:
            end_text = end_text.replace('T', ' ')

        st = _parse_dt(start_text)
        if st is None:
            en_def = get_last_thursday_at_9am()
            st = en_def - timedelta(days=7)
        en = _parse_dt(end_text)
        if en is None:
            en = get_last_thursday_at_9am()

        return {
            'cidr': cidr,
            'start_iso': st.strftime('%Y-%m-%dT%H:%M:%S'),
            'end_iso': en.strftime('%Y-%m-%dT%H:%M:%S'),
            'start_str': st.strftime('%Y-%m-%d %H:%M:%S'),
            'end_str': en.strftime('%Y-%m-%d %H:%M:%S'),
            'submitted': bool(n_clicks),
        }

    @app.callback(
        [Output(f'search-{w}-time-label', 'children') for w in SEARCH_WIDGET_KEYS],
        Input('search-params', 'data'),
        prevent_initial_call=False
    )
    def update_search_time_labels(params):
        params = params or {}
        start = params.get('start_str', '')
        end = params.get('end_str', '')
        label = f"{start}  ->  {end}"
        return [label] * len(SEARCH_WIDGET_KEYS)

    @app.callback(
        Output('search-error', 'children'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def render_search_error(params, n_intervals):
        cidr, start, end, submitted = _parse_params(params)
        if not submitted:
            return ''
        if not cidr:
            return 'Enter a CIDR to search.'
        try:
            _validate_cidr(cidr)
        except Exception as e:
            return f'Invalid CIDR "{cidr}": {e}'
        return ''

    @app.callback(
        Output('search-alerts-table', 'rowData'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_search_alerts(params, n_intervals):
        cidr, start, end, submitted = _parse_params(params)
        if not submitted or not cidr:
            return []
        try:
            _validate_cidr(cidr)
        except Exception:
            return []
        try:
            df = get_alerts_for_search(cidr, start, end)
        except Exception as e:
            print(f"[search] alerts error: {e}")
            return []
        if df.empty:
            return []
        # same link trick as alert_interactive.py:100 — clickable UID -> /alert/<uid>
        df['alert_uid'] = df['alert_uid'].apply(lambda x: f"[{x}](/alert/{x})")

        # Mirrors alert_interactive.py:load_alerts_data so the level
        # / WAF Blocks / DP Blocks columns in alerts_columnDefs render the same
        # way they do on the live alerts page.
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

        return df.to_dict('records')

    @app.callback(
        Output('search-genie-table', 'rowData'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_search_genie(params, n_intervals):
        cidr, start, end, submitted = _parse_params(params)
        if not submitted or not cidr:
            return []
        try:
            _validate_cidr(cidr)
        except Exception:
            return []
        try:
            df = get_genie_events_for_search(cidr, start, end)
        except Exception as e:
            print(f"[search] genie error: {e}")
            return []
        if df.empty:
            return []

        # Row prep mirrors register_alert_detail_callbacks::load_alert_details
        # (alert_interactive.py) so genie_columnDefs lines up exactly.
        df['resource'] = df['resource'].apply(lambda x: str(x))
        df['last_update'] = pd.to_datetime(df['last_update']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df['start'] = df['start'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))
        df['end'] = df['end'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, datetime) and len(str(x)) > 5 else '')
        df['target_network'] = df['target_network'].apply(lambda x: str(x))
        df['target_broadcast'] = df['target_broadcast'].apply(lambda x: str(x))
        df['max_pps'] = df['max_pps'].apply(lambda x: x if x else 0)
        df['max_bps'] = df['max_bps'].apply(lambda x: x if x else 0)

        def range_to_cidr(start_ip, end_ip):
            s = ipaddress.IPv4Address(start_ip)
            e = ipaddress.IPv4Address(end_ip)
            total = int(e) - int(s) + 1
            prefix = 32 - (total.bit_length() - 1)
            return str(ipaddress.IPv4Network(f"{s}/{prefix}", strict=False))
        df['Target CIDR'] = df.apply(lambda r: range_to_cidr(r['target_network'], r['target_broadcast']), axis=1)
        df['Importance'] = 1
        df['Data Source'] = 'Genie'

        return df.to_dict(orient='records')

    @app.callback(
        Output('search-dp-output', 'children'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_search_dp(params, n_intervals):
        cidr, start, end, submitted = _parse_params(params)
        if not submitted or not cidr:
            return ''
        try:
            _validate_cidr(cidr)
        except Exception:
            return ''

        # --- text totals (search window only) ---
        try:
            dp_data = get_dp_data(cidr, start, end, top_descriptions_num=10)
        except Exception as e:
            print(f"[search] dp error: {e}")
            return html.Pre(str(e), className='data-pre')

        if 'aggregations' not in dp_data or 'top_drop_descriptions' not in dp_data['aggregations']:
            return html.Pre("No DP data", className='data-pre')

        dp_agg = dp_data['aggregations']

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
                _compute_histogram_window(start, end)
            ts = get_dp_drops_timeseries(
                cidr,
                window_start.strftime('%Y-%m-%d %H:%M:%S'),
                window_end.strftime('%Y-%m-%d %H:%M:%S'),
                interval=interval,
            )
        except Exception as e:
            print(f"[search] dp timeseries error: {e}")
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

        span_seconds = (window_end - window_start).total_seconds()
        bar_width_ms = _interval_to_ms(interval)

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

        fig = go.Figure(traces)
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
        Output('search-waf-output', 'children'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_search_waf(params, n_intervals):
        cidr, start, end, submitted = _parse_params(params)
        if not submitted or not cidr:
            return ''
        try:
            _validate_cidr(cidr)
        except Exception:
            return ''

        # --- histogram + totals from timeseries ---
        try:
            window_start, window_end, alert_start, alert_end, interval, ongoing = \
                _compute_histogram_window(start, end)
            ts = get_waf_decisions_timeseries(
                cidr,
                window_start.strftime('%Y-%m-%d %H:%M:%S'),
                window_end.strftime('%Y-%m-%d %H:%M:%S'),
                interval=interval,
            )
        except Exception as e:
            print(f"[search] waf timeseries error: {e}")
            # Fall back to legacy aggregated call so the text block still shows.
            try:
                pass_blocks = waf_blocks_by_net(cidr, start, end, timeout=60)
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

        # Aggregate totals over the full window for the text block.
        totals = {}
        for b in ts:
            for sb in b['buckets']:
                totals[sb['key']] = totals.get(sb['key'], 0) + sb['doc_count']

        # No real activity across the whole window — keep the "(no activity)"
        # text block and skip the empty graph.
        if not totals or sum(totals.values()) == 0:
            return _build_waf_text_pre(totals)

        text_pre = _build_waf_text_pre(totals)

        span_seconds = (window_end - window_start).total_seconds()
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

    @app.callback(
        Output('search-sources-ip-pie', 'figure'),
        Output('search-sources-country-pie', 'figure'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def load_search_sources(params, n_intervals):
        cidr, start, end, submitted = _parse_params(params)
        empty_ip = _pie_fig([], [], 'Source IPs')
        empty_country = _pie_fig([], [], 'Source Countries')
        if not submitted or not cidr:
            return empty_ip, empty_country
        try:
            _validate_cidr(cidr)
        except Exception:
            return empty_ip, empty_country
        try:
            buckets = get_top_attack_sources(start, end, cidr=cidr, size=11)
        except Exception as e:
            print(f"[search] sources error: {e}")
            return empty_ip, empty_country

        # filter 0.0.0.0 and zero counts (mirrors _build_pie_drawing)
        filtered = [(b['key'], b['doc_count']) for b in buckets
                    if b.get('key') != '0.0.0.0' and b.get('doc_count', 0)]
        if not filtered:
            return empty_ip, empty_country

        ip_labels = [ip for ip, _ in filtered]
        ip_values = [c for _, c in filtered]
        ip_fig = _pie_fig(ip_labels, ip_values, 'Source IPs')

        # Country aggregation via reports_pdf_alt._fetch_top_source_countries
        # (CIDR-filtered, size=1000 internally) so the web page matches the
        # search PDF exactly.
        country_bins = _fetch_top_source_countries(start, end, cidr=cidr, size=10)
        if country_bins:
            c_labels = [b['label'] for b in country_bins]
            c_values = [b['count'] for b in country_bins]
            country_fig = _pie_fig(c_labels, c_values, 'Source Countries')
        else:
            country_fig = empty_country
        return ip_fig, country_fig

    # ---- NetFlow extended CIDR info --------------------------------------

    def _render_flow_side(side_data, title_prefix):
        """Shared renderer for both as_source and as_destination blocks."""
        empty_left  = html.Div('No data', className='kv-value')
        empty_right = html.Div('No data', className='kv-value')
        empty_fig   = _flow_empty_fig(title_prefix)
        if not side_data:
            return empty_left, empty_right, empty_fig

        left = []
        left.extend(_flow_overview_block(side_data['overview']))
        left.extend(_flow_section('Top src IPs',
                                  _flow_toplist(side_data['top_src_ips'])))
        left.extend(_flow_section('Top src ports',
                                  _flow_toplist(side_data['top_src_ports'])))
        left.extend(_flow_section('Top dst IPs',
                                  _flow_toplist(side_data['top_dst_ips'])))

        right = []
        right.extend(_flow_section('Top dst ports',
                                   _flow_toplist(side_data['top_dst_ports'])))
        right.extend(_flow_section('Top protocols',
                                   _flow_toplist(side_data['top_protocols'],
                                                 key_fmt=_proto_to_string)))
        right.extend(_flow_section('Top TCP flags',
                                   _flow_toplist(side_data['top_tcp_flags'],
                                                 key_fmt=_tcp_flag_int_to_string)))
        right.append(_flow_stats_block(side_data['stats']))

        ts = side_data.get('timeseries') or {}
        fig = _flow_timeseries_fig(ts.get('points', []),
                                   ts.get('bucket', 'minute'),
                                   title_prefix)
        return html.Div(left), html.Div(right), fig

    @app.callback(
        Output('search-flow-src-left', 'children'),
        Output('search-flow-src-right', 'children'),
        Output('search-flow-src-graph', 'figure'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def render_flow_src(params, n_intervals):
        cidr, start_iso, end_iso, submitted = _parse_flow_params(params)
        empty_left  = html.Div('No data', className='kv-value')
        empty_right = html.Div('No data', className='kv-value')
        empty_fig   = _flow_empty_fig('NetFlow: CIDR as source')
        if not submitted or not cidr:
            return empty_left, empty_right, empty_fig
        try:
            _validate_cidr(cidr)
        except Exception:
            return empty_left, empty_right, empty_fig
        side_data = flow_api_fetch_as_source(cidr, start_iso, end_iso, FLOW_API_TOP_N)
        return _render_flow_side(side_data, 'NetFlow: CIDR as source')

    @app.callback(
        Output('search-flow-dst-left', 'children'),
        Output('search-flow-dst-right', 'children'),
        Output('search-flow-dst-graph', 'figure'),
        Input('search-params', 'data'),
        Input('search-autoupdate-interval', 'n_intervals'),
        prevent_initial_call=False
    )
    def render_flow_dst(params, n_intervals):
        cidr, start_iso, end_iso, submitted = _parse_flow_params(params)
        empty_left  = html.Div('No data', className='kv-value')
        empty_right = html.Div('No data', className='kv-value')
        empty_fig   = _flow_empty_fig('NetFlow: CIDR as destination')
        if not submitted or not cidr:
            return empty_left, empty_right, empty_fig
        try:
            _validate_cidr(cidr)
        except Exception:
            return empty_left, empty_right, empty_fig
        side_data = flow_api_fetch_as_destination(cidr, start_iso, end_iso, FLOW_API_TOP_N)
        return _render_flow_side(side_data, 'NetFlow: CIDR as destination')


def create_search_app(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.CYBORG, '/static/styles.css'],
               external_scripts=['/static/ag_grid_custom_filters.js'])

    app.layout = search_layout()
    register_search_callbacks(app)

    export_route = url_base_pathname + 'export-pdf'

    @server.route(export_route)
    def search_export_pdf():
        start = request.args.get('start')
        end = request.args.get('end')
        if not start or not end:
            en = get_last_thursday_at_9am()
            st = en - timedelta(days=7)
            start = st.strftime('%Y-%m-%dT%H:%M:%S')
            end = en.strftime('%Y-%m-%dT%H:%M:%S')
        cidr = request.args.get('cidr', '')
        widgets_param = request.args.get('widgets', '')
        widgets = [w for w in widgets_param.split(',') if w] if widgets_param else None
        try:
            pdf_bytes = build_search_pdf(start, end, cidr=cidr or None, widgets=widgets)
        except Exception as e:
            return Response(f"PDF generation failed: {e}", status=500, mimetype='text/plain')

        filename = f"search_report_{start.replace(':', '-').replace(' ', '_')}_{end.replace(':', '-').replace(' ', '_')}.pdf"
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    return app

