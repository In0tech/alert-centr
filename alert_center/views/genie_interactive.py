from flask import Blueprint, render_template

bp = Blueprint("interactive", __name__, url_prefix="/interactive")

from dash import Dash, html, dcc, dash_table, callback_context
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
from datetime import datetime, timedelta, timezone
import pandas as pd

from dash import Dash, html, dcc
import plotly.graph_objs as go
import random
import pytz
from collections import defaultdict

from services.data_fetcher import get_genie_events, get_genie_traffic

from alert_center.views.theme import STYLE


TOP = 3
TOP_PROTO = 20


def proto_to_string(proto):
    match(str(proto)):
        case '1':
            return "ICMP (1)"
        case '4':
            return "IP-in-IP (4)"
        case '6':
            return "TCP (6)"
        case '17':
            return "UDP (17)"
        case '41':
            return "IPv6 (41)"
        case '47':
            return "GRE (47)"
        case '50':
            return "ESP (50)"
        case '58':
            return "ICMPv6 (58)"
        case '89':
            return "OSPF (89)"
        case '121':
            return "SMP (121)"
        case _:
            return f"Proto №{proto}"


def iso_now_utc():
    return datetime.now().replace(microsecond=0)


def default_last_hour():
    end = datetime.now().replace(microsecond=0)
    start = end - timedelta(hours=1)
    return start, end


def default_last_day():
    end = datetime.now().replace(microsecond=0)
    start = end - timedelta(days=1)
    return start, end


def time_range_controls(prefix, start_def, end_def):
    def _fmt(v):
        if isinstance(v, datetime):
            return v.strftime('%Y-%m-%dT%H:%M:%S')
        return v
    start_def = _fmt(start_def)
    end_def = _fmt(end_def)
    return html.Div([
        html.Button('Last 15m', id=f'{prefix}-q-15m', className='btn btn-outline'),
        html.Button('Last 1h', id=f'{prefix}-q-1h', className='btn btn-outline'),
        html.Button('Last 24h', id=f'{prefix}-q-24h', className='btn btn-outline'),
        html.Button('Last 7d', id=f'{prefix}-q-7d', className='btn btn-outline'),
        dcc.Input(id=f'{prefix}-start', type='datetime-local', value=start_def,
                  step=1, style={'width': '200px'}),
        dcc.Input(id=f'{prefix}-end', type='datetime-local', value=end_def,
                  step=1, style={'width': '200px'}),
        html.Button('Use range', id=f'{prefix}-update'),
        #dcc.Interval(id=f'{prefix}-interval', interval=6000 * 1000, n_intervals=0, disabled=True),
        dcc.Interval(id=f'{prefix}-interval', interval=30 * 1000, n_intervals=0, disabled=True),
        dbc.Switch(id=f'{prefix}-autoupdate', value=False, label='Auto-update (30s)',
                   class_name='autoupdate-switch'),
    ], className='time-controls')


def register_autoupdate_toggle(app, prefix):
    @app.callback(
        Output(f'{prefix}-interval', 'disabled'),
        Input(f'{prefix}-autoupdate', 'value'),
    )
    def _toggle_autoupdate(enabled):
        return not bool(enabled)


def context_time_filter(ctx, prefix, start=None, end=None):
    ctx = callback_context

    if ctx.triggered:
        tr = ctx.triggered[0]['prop_id'].split('.')[0]
        now_iso = iso_now_utc()
        if tr == f'{prefix}-q-15m':
            s = (datetime.now().replace(microsecond=0) - timedelta(minutes=15)); e = now_iso
            start, end = s, None
        elif tr == f'{prefix}-q-1h':
            s = (datetime.now().replace(microsecond=0) - timedelta(hours=1)); e = now_iso
            start, end = s, None
        elif tr == f'{prefix}-q-24h':
            s = (datetime.now().replace(microsecond=0) - timedelta(hours=24)); e = now_iso
            start, end = s, None
        elif tr == f'{prefix}-q-7d':
            s = (datetime.now().replace(microsecond=0) - timedelta(days=7)); e = now_iso
            start, end = s, None
        elif tr == f'{prefix}-update':
            pass
        else:
            start, end = default_last_hour()

    return start, end


from plotly.graph_objects import Layout
import plotly.io as pio


def _empty_anomaly_fig():
    fig = go.Figure()
    fig.update_layout(
        margin=dict(l=60, r=10, t=30, b=40),
        height=300,
        paper_bgcolor=STYLE['chart_paper_bg'],
        plot_bgcolor=STYLE['chart_plot_bg'],
        font=dict(color=STYLE['text_muted'], size=STYLE['chart_font_size']),
        xaxis=dict(gridcolor=STYLE['chart_grid'], tickformat='%H:%M'),
        yaxis=dict(gridcolor=STYLE['chart_grid']),
        bargap=0,
    )
    return fig


fig = _empty_anomaly_fig()


def _format_bps_label(val):
    if val is None:
        return ''
    v = abs(val)
    if v >= 1e9:
        return f"{val/1e9:.2f} Gbps"
    elif v >= 1e6:
        return f"{val/1e6:.2f} Mbps"
    elif v >= 1e3:
        return f"{val/1e3:.2f} kbps"
    return f"{val:.0f} bps"


def anomaly_traffic_widget(prefix='anomaly-traffic'):
    return html.Div([
        html.Div([
            html.I(className='bi bi-graph-up me-2'),
            html.H4('Anomaly Traffic')
        ], className='card-section-header'),
        html.Div([
            time_range_controls(prefix, *default_last_day()),
            dcc.Loading([
                dcc.Graph(id=f'{prefix}-chart', figure=fig, config={'displayModeBar': False, 'displaylogo': False}),
            ], type="dot"),
            html.Div(id=f'{prefix}-out')
        ], className='card-section-body')
    ], className='card-section')


def register_anomaly_traffic_callbacks(app):
    @app.callback(
        Output('anomaly-traffic-chart', 'figure'),
        Input('anomaly-traffic-update', 'n_clicks'),
        Input('anomaly-traffic-interval', 'n_intervals'),
        Input('anomaly-traffic-q-15m', 'n_clicks'),
        Input('anomaly-traffic-q-1h', 'n_clicks'),
        Input('anomaly-traffic-q-24h', 'n_clicks'),
        Input('anomaly-traffic-q-7d', 'n_clicks'),
        State('anomaly-traffic-start', 'value'),
        State('anomaly-traffic-end', 'value'),
        prevent_initial_call=False
    )
    def update_anomaly_traffic(n_update, n_interval, q15, q1, q24, q7d, start, end):
        start, end = context_time_filter(callback_context, 'anomaly-traffic', start, end)

        if isinstance(start, str):
            try:
                start = pd.to_datetime(start)
            except Exception:
                start = None
        if isinstance(end, str):
            try:
                end = pd.to_datetime(end)
            except Exception:
                end = None

        if start is None:
            start = datetime.now().replace(microsecond=0) - timedelta(days=1)
        if end is None:
            end = datetime.now().replace(microsecond=0)

        rows = get_genie_traffic(start, end)

        start_msk = start.replace(second=0, microsecond=0).astimezone(pytz.timezone('Europe/Moscow'))
        end_msk = end.replace(second=0, microsecond=0).astimezone(pytz.timezone('Europe/Moscow'))
        times = pd.date_range(start=start_msk, end=end_msk, freq='min')

        bars = defaultdict(int)
        for row in rows:
            for time in times:
                if time >= row[1] and time <= row[2] if row[2] else time <= end_msk:
                    bars[time] += row[3]

        fig = go.Figure(go.Bar(
            x=list(bars.keys()),
            y=list(bars.values()),
            marker_color=STYLE['accent_cyan'],
        ))
        fig.update_layout(
            margin=dict(l=60, r=10, t=30, b=40),
            height=300,
            paper_bgcolor=STYLE['chart_paper_bg'],
            plot_bgcolor=STYLE['chart_plot_bg'],
            font=dict(color=STYLE['text_muted'], size=STYLE['chart_font_size']),
            xaxis=dict(
                title='Time',
                gridcolor=STYLE['chart_grid'],
                tickformat='%H:%M',
            ),
            yaxis=dict(
                title='Traffic',
                gridcolor=STYLE['chart_grid'],
                tickvals=[],
                ticktext=[],
            ),
            bargap=0,
        )

        if bars:
            import numpy as np
            y_vals = list(bars.values())
            max_val = max(y_vals)
            nice_ticks = np.linspace(0, max_val, num=6)
            fig.update_layout(yaxis=dict(
                title='Traffic',
                gridcolor=STYLE['chart_grid'],
                tickvals=nice_ticks.tolist(),
                ticktext=[_format_bps_label(v) for v in nice_ticks],
            ))

        return fig


import dash_ag_grid as dag
from dash import Dash, html

from alert_center.views.theme import grid_ag_theme, genie_columnDefs


def anomaly_table_widget(prefix='anomaly-table'):
    return html.Div([
        html.Div([
            html.I(className='bi bi-table me-2'),
            html.H4('Last Anomalies')
        ], className='card-section-header'),
        html.Div([
            time_range_controls(prefix, *default_last_hour()),
            html.Div(id=f'{prefix}-out'),
            dag.AgGrid(
                id="filter-options-example-simple",
                columnDefs=genie_columnDefs,
                columnSize="sizeToFit",
                defaultColDef={"filter": "agTextColumnFilter"},
                dashGridOptions={"enableCellTextSelection": True, "ensureDomOrder": True,
                                  "animateRows": True,
                                  "theme": grid_ag_theme},
            ),
        ], className='card-section-body')
    ], className='card-section')


def register_anomaly_table_callbacks(app):
    @app.callback(
        Output("filter-options-example-simple", "rowData"),

        Input('anomaly-table-update', 'n_clicks'),
        Input('anomaly-table-interval', 'n_intervals'),
        Input('anomaly-table-q-15m', 'n_clicks'),
        Input('anomaly-table-q-1h', 'n_clicks'),
        Input('anomaly-table-q-24h', 'n_clicks'),
        Input('anomaly-table-q-7d', 'n_clicks'),
        State('anomaly-table-start', 'value'),
        State('anomaly-table-end', 'value'),
        prevent_initial_call=False
    )
    def update_anomaly_table(n_update, n_interval, q15, q1, q24, q7d, start, end):
        start, end = context_time_filter(callback_context, 'anomaly-table', start, end)

        df = get_genie_events(start, end)

        df['resource'] = df['resource'].apply(lambda x: str(x))

        df['last_update'] = df['last_update'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))
        df['start'] = df['start'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))
        df['end'] = df['end'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, datetime) and len(str(x)) > 5 else '')

        df['target_network'] = df['target_network'].apply(lambda x: str(x))
        df['target_broadcast'] = df['target_broadcast'].apply(lambda x: str(x))

        df['max_pps'] = df['max_pps'].apply(lambda x: x if x else 0)
        df['max_bps'] = df['max_bps'].apply(lambda x: x if x else 0)

        import ipaddress
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

        data = df.to_dict(orient='records')

        return data


def create_genie_dash(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.CYBORG, '/static/styles.css'])
    app.layout = html.Div([
        anomaly_traffic_widget(),
        anomaly_table_widget(),
    ], style={'display': 'flex', 'flexDirection': 'column', 'width': '100%', 'minHeight': '100vh', 'padding': '16px', 'gap': '16px'})

    register_anomaly_traffic_callbacks(app)
    register_anomaly_table_callbacks(app)
    register_autoupdate_toggle(app, 'anomaly-traffic')
    register_autoupdate_toggle(app, 'anomaly-table')

    return app

