from flask import Blueprint, render_template, request, Response
from dash import Dash, html, dcc, callback_context
from dash import dash, dcc, html, callback, Input, Output
from dash.dependencies import Input, Output, State
import dash_bootstrap_components as dbc
import pandas as pd
from datetime import datetime, timedelta

import dash_ag_grid as dag
from alert_center.views.theme import grid_ag_theme, alerts_columnDefs


import plotly.graph_objects as go
from services.data_fetcher import (
    get_vc_it_elk_summary,
    get_vc_it_genie_summary,
    get_b2b_summary,
    get_shpd_genie_summary,
    get_top_radware_summary,
    get_vc_it_extra_stats,
    get_b2b_extra_stats,
    get_shpd_extra_stats,
    get_top_alerts_by_bps,
    get_top_alerts_by_duration,
    format_datetime_for_query,
)
from services.utils import c_rounding, sec_to_str, get_last_thursday_at_9am, resolve_ip, hist_pct
from alert_center.views.theme import STYLE
from alert_center.views.reports_pdf import build_reports_pdf
from alert_center.views.reports_pdf_alt import build_reports_pdf_alt


def reports_time_controls():
    en = get_last_thursday_at_9am()
    st = en - timedelta(days=7)
    start_def = st.strftime('%Y-%m-%dT%H:%M:%S')
    end_def = en.strftime('%Y-%m-%dT%H:%M:%S')
    return html.Div([
        html.Div([
            html.Div([
                html.Button('Last 1h', id='reports-time-q-1h', className='btn btn-outline'),
                html.Button('Last 24h', id='reports-time-q-24h', className='btn btn-outline'),
                html.Button('Last 7d', id='reports-time-q-7d', className='btn btn-outline'),
                dcc.Input(id='reports-time-start', type='datetime-local', value=start_def,
                          step=1, style={'width': '200px'}),
                dcc.Input(id='reports-time-end', type='datetime-local', value=end_def,
                          step=1, style={'width': '200px'}),
                html.Button('Use range', id='reports-time-update', className='btn btn-outline'),
                dcc.Dropdown(
                    id='reports-widget-selector',
                    options=[
                        {'label': 'B2B',         'value': 'b2b'},
                        {'label': 'ВК ИТ',       'value': 'vc_it'},
                        {'label': 'ШПД',         'value': 'shpd'},
                        {'label': 'ТОП рес. ВК', 'value': 'qlik'},
                    ],
                    value=['b2b', 'vc_it', 'shpd', 'qlik'],
                    multi=True,
                    placeholder='Widgets…',
                    className='reports-widget-dropdown',
                    optionHeight=35,
                ),
                html.A('Export PDF', id='reports-export-pdf', className='btn btn-outline',
                       target='_blank', href='#'),
                html.A('Export PDF (alt)', id='reports-export-pdf-alt', className='btn btn-outline',
                       target='_blank', href='#'),
                dbc.Switch(id='reports-autoupdate', value=False, label='Auto-update (60s)',
                           class_name='autoupdate-switch'),
                dcc.Interval(id='reports-autoupdate-interval', interval=60000, n_intervals=0, disabled=True),
            ], className='time-controls', style={'marginBottom': '0'}),
            dcc.Store(id='reports-time-range'),
        ], className='card-section-body'),
    ], className='card-section mb-3')


def reports_resolve_time(ctx):
    if not ctx.triggered:
        en = get_last_thursday_at_9am()
        st = en - timedelta(days=7)
        return st, en
    tr = ctx.triggered[0]['prop_id'].split('.')[0]
    now = datetime.now().replace(microsecond=0)
    if tr == 'reports-time-q-1h':
        return now - timedelta(hours=1), now
    if tr == 'reports-time-q-24h':
        return now - timedelta(hours=24), now
    if tr == 'reports-time-q-7d':
        return now - timedelta(days=7), now
    # reports-time-update -> parse inputs, handled by caller
    return None, None


def format_timestamp(timestamp):
    try:
        dt = pd.to_datetime(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(timestamp)


def dict_to_kv_html(dct, indent=0):
    items = []
    for k, v in dct.items():
        if isinstance(v, dict):
            items.append(html.Div([
                html.Div(k, className='kv-group-label'),
                dict_to_kv_html(v, indent=indent + 1)
            ], className='kv-group'))
        else:
            val = str(v)
            if '\n' in val:
                items.append(html.Div([
                    html.Span(f"{k}:", className='kv-key'),
                    html.Span(val, className='kv-value', style={'whiteSpace': 'pre-line'}),
                ], className='kv-row'))
            else:
                items.append(html.Div([
                    html.Span(f"{k}:", className='kv-key'),
                    html.Span(val, className='kv-value')
                ], className='kv-row'))
    return html.Div(items)


def summary_card(card_id, title, subtitle=None):
    header_children = [html.I(className='bi bi-bar-chart-fill me-2'), html.H4(title)]
    if subtitle:
        header_children.append(html.Small(subtitle, className='ms-auto', style={'color': 'var(--text-muted)', 'fontSize': '12px'}))

    return html.Div([
        html.Div(header_children, className='card-section-header'),
        html.Div([
            dcc.Loading([html.Div(id=card_id)], type="dot")
        ], className='card-section-body')
    ], className='card-section')


def table_card(card_id, title, column_defs, height='220px'):
    return html.Div([
        html.Div([
            html.I(className='bi bi-table me-2'),
            html.H4(title)
        ], className='card-section-header'),
        html.Div([
            dag.AgGrid(
                id=card_id,
                columnDefs=column_defs,
                columnSize="sizeToFit",
                defaultColDef={"filter": "agTextColumnFilter"},
                dashGridOptions={
                    "enableCellTextSelection": True,
                    "ensureDomOrder": True,
                    "animateRows": True,
                    "theme": grid_ag_theme
                },
                style={'height': height}
            ),
        ], className='card-section-body')
    ], className='card-section')



#    {"field": "START_TIME", "filter": "DateRangeFilter", "filterParams": {"buttons": ["reset"]}},
#    {"field": "END_TIME", "filter": "DateRangeFilter", "filterParams": {"buttons": ["reset"]}},
def reports_layout():
    bps_columns = [
        {"field": "UID", "filter": "agTextColumnFilter"},
        {"field": "TARGET_CIDR", "filter": "agTextColumnFilter"},
        {"field": "START_TIME", "filter": "agTextColumnFilter"},
        {"field": "END_TIME", "filter": "agTextColumnFilter"},
        {"field": "CURRENT_MAX_BPS", "filter": "agNumberColumnFilter",
         "valueFormatter": {"function":
            "Math.abs(Number(params.value) || 0) >= 1e9 ? (Number(params.value)/1e9).toFixed(2) + ' Gbps' : "
            "(Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + ' Mbps' : "
            "(Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + ' kbps' : "
            "(Number(params.value) || 0) + ' bps'))"}
        },
    ]

    duration_columns = [
        {"field": "UID", "filter": "agTextColumnFilter"},
        {"field": "TARGET_CIDR", "filter": "agTextColumnFilter"},
        {"field": "START_TIME", "filter": "agTextColumnFilter"},
        {"field": "END_TIME", "filter": "agTextColumnFilter"},
        {"field": "duration_seconds", "filter": "agNumberColumnFilter", "headerName": "Duration (s)"},
        {"field": "CURRENT_MAX_BPS", "filter": "agNumberColumnFilter",
         "valueFormatter": {"function":
            "Math.abs(Number(params.value) || 0) >= 1e9 ? (Number(params.value)/1e9).toFixed(2) + ' Gbps' : "
            "(Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + ' Mbps' : "
            "(Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + ' kbps' : "
            "(Number(params.value) || 0) + ' bps'))"}
        },
    ]

    return html.Div([
        dcc.Location(id='url'),

        reports_time_controls(),

        html.Div([
            html.Div([
                html.I(className='bi bi-bar-chart-fill me-2'),
                html.H4('Итоги')
            ], className='card-section-header'),
            html.Div([
                dcc.Loading([html.Div(id='b2b-totals')], type="dot")
            ], className='card-section-body')
        ], className='card-section mb-3'),

        html.Div([
            dbc.Row([
                dbc.Col([summary_card('b2b-summary', 'Отчёт: B2B')], md=6),
                dbc.Col([summary_card('b2b-stats', 'Статистика B2B')], md=6),
            ], className='mb-3'),
        ], id='reports-widget-b2b'),

        html.Div([
            dbc.Row([
                dbc.Col([summary_card('vc-it-summary', 'Отчёт: ВК ИТ')], md=6),
                dbc.Col([summary_card('vc-it-stats', 'Статистика ВК ИТ')], md=6),
            ], className='mb-3'),
        ], id='reports-widget-vc_it'),

        html.Div([
            dbc.Row([
                dbc.Col([summary_card('shpd-summary', 'Отчёт: ШПД')], md=6),
                dbc.Col([summary_card('shpd-stats', 'Статистика ШПД')], md=6),
            ], className='mb-3'),
        ], id='reports-widget-shpd'),

        html.Div([
            dbc.Row([
                dbc.Col([summary_card('qlik-summary', 'ТОП атакуемых ресурсов ВК')], md=12),
            ], className='mb-3'),
        ], id='reports-widget-qlik'),


        
    ], className='page-container')

'''
        html.Div([
            html.Div([
                html.Div([
                    html.I(className='bi bi-lightning-fill me-2'),
                    html.H4('Top Alerts by BPS')
                ], className='card-section-header'),
                html.Div([
                    dbc.Row([
                        dbc.Col([
                            html.Div('Last 24 Hours', className='section-subtitle'),
                            dag.AgGrid(
                                id='top-bps-24h-table',
                                columnDefs=bps_columns,
                                columnSize="sizeToFit",
                                defaultColDef={"filter": "agTextColumnFilter"},
                                dashGridOptions={
                                    "enableCellTextSelection": True,
                                    "ensureDomOrder": True,
                                    "animateRows": True,
                                    "theme": grid_ag_theme
                                },
                                style={'height': '200px'}
                            ),
                        ], md=6),
                        dbc.Col([
                            html.Div('Last 7 Days', className='section-subtitle'),
                            dag.AgGrid(
                                id='top-bps-7d-table',
                                columnDefs=bps_columns,
                                columnSize="sizeToFit",
                                defaultColDef={"filter": "agTextColumnFilter"},
                                dashGridOptions={
                                    "enableCellTextSelection": True,
                                    "ensureDomOrder": True,
                                    "animateRows": True,
                                    "theme": grid_ag_theme
                                },
                                style={'height': '200px'}
                            ),
                        ], md=6),
                    ]),
                ], className='card-section-body')
            ], className='card-section mb-3'),


        ], id='reports-widget-extra'),
        
        
        
            html.Div([
                html.Div([
                    html.I(className='bi bi-clock-fill me-2'),
                    html.H4('Top Alerts by Duration')
                ], className='card-section-header'),
                html.Div([
                    dbc.Row([
                        dbc.Col([
                            html.Div('Last 24 Hours', className='section-subtitle'),
                            dag.AgGrid(
                                id='top-duration-24h-table',
                                columnDefs=duration_columns,
                                columnSize="sizeToFit",
                                defaultColDef={"filter": "agTextColumnFilter"},
                                dashGridOptions={
                                    "enableCellTextSelection": True,
                                    "ensureDomOrder": True,
                                    "animateRows": True,
                                    "theme": grid_ag_theme
                                },
                                style={'height': '200px'}
                            ),
                        ], md=6),
                        dbc.Col([
                            html.Div('Last 7 Days', className='section-subtitle'),
                            dag.AgGrid(
                                id='top-duration-7d-table',
                                columnDefs=duration_columns,
                                columnSize="sizeToFit",
                                defaultColDef={"filter": "agTextColumnFilter"},
                                dashGridOptions={
                                    "enableCellTextSelection": True,
                                    "ensureDomOrder": True,
                                    "animateRows": True,
                                    "theme": grid_ag_theme
                                },
                                style={'height': '200px'}
                            ),
                        ], md=6),
                    ]),
                ], className='card-section-body')
            ], className='card-section mb-3'),
'''


def build_summary_display(start, end, note_text, data_dict):
    children = [
        html.Div(f"{start}  ->  {end}", className='time-range-label'),
    ]
    if note_text:
        children.append(html.Div(note_text, className='section-subtitle'))

    if isinstance(data_dict, dict):
        children.append(dict_to_kv_html(data_dict))
    else:
        children.append(html.Div(str(data_dict), className='kv-value'))

    return html.Div(children)


def _hist_layout_defaults(title):
    """Shared plotly layout for the BPS / Duration histograms.

    Sourced from STYLE so the Dash charts and the PDF export stay cohesive.
    """
    return dict(
        title=title,
        margin=dict(l=40, r=10, t=30, b=60),
        height=220,
        paper_bgcolor=STYLE['chart_paper_bg'],
        plot_bgcolor=STYLE['chart_plot_bg'],
        font=dict(color=STYLE['text_muted'], size=STYLE['chart_font_size']),
        xaxis=dict(tickangle=-45, tickfont=dict(size=8)),
        yaxis=dict(title='% of total', gridcolor=STYLE['chart_grid']),
    )

def _build_stats_children(stats, time_range_str=None):
    children = []
    if time_range_str:
        children.append(html.Div(time_range_str, className='time-range-label'))
    if stats['avg_bps'] is None:
        children.append(html.Div('No data', className='kv-value'))
        return html.Div(children)

    desc = {
        'avg_bps': c_rounding(stats['avg_bps'], 'bps'),
        'median_bps': c_rounding(stats['median_bps'], 'bps'),
        #'variance_bps': c_rounding(stats['variance_bps'], 'bps') if stats['variance_bps'] else 'N/A',
        'stddev_bps': c_rounding(stats['stddev_bps'], 'bps') if stats['stddev_bps'] else 'N/A',
        'avg_duration': sec_to_str(stats['avg_duration']),
        'median_duration': sec_to_str(stats['median_duration']),
        #'variance_duration': sec_to_str(round(stats['variance_duration'])) if stats['variance_duration'] else 'N/A',
        'stddev_duration': sec_to_str(round(stats['stddev_duration'])) if stats['stddev_duration'] else 'N/A',
    }
    children.append(html.Div('Descriptive stats', className='section-subtitle'))
    children.append(dict_to_kv_html(desc))

    '''if stats['duration_breakdown']:
        db = stats['duration_breakdown']
        breakdown_display = {
            '<= 1 min': f"{db['under_1min']['count']} ({db['under_1min']['pkt']}%)",
            '1-5 min': f"{db['one_to_5min']['count']} ({db['one_to_5min']['pkt']}%)",
            '5-60 min': f"{db['five_to_60min']['count']} ({db['five_to_60min']['pkt']}%)",
            '> 1 hour': f"{db['over_1hour']['count']} ({db['over_1hour']['pkt']}%)",
        }
        children.append(html.Div('Duration breakdown', className='section-subtitle'))
        children.append(dict_to_kv_html(breakdown_display))'''

    if stats['bps_histogram']:
        bins = stats['bps_histogram']
        x_labels = [b.get('label', '') for b in bins]
        pkts = [hist_pct(b) for b in bins]
        fig_bps = go.Figure([go.Bar(x=x_labels, y=pkts, marker_color=STYLE['accent_bps'])])
        fig_bps.update_layout(_hist_layout_defaults('BPS distribution'))
        children.append(dcc.Graph(figure=fig_bps, config={'displayModeBar': False}))

    if stats['duration_histogram']:
        bins = stats['duration_histogram']
        x_labels = [b.get('label', '') for b in bins]
        pkts = [hist_pct(b) for b in bins]
        fig_dur = go.Figure([go.Bar(x=x_labels, y=pkts, marker_color=STYLE['accent_duration'])])
        fig_dur.update_layout(_hist_layout_defaults('Duration distribution'))
        children.append(dcc.Graph(figure=fig_dur, config={'displayModeBar': False}))

    return html.Div(children)


def register_reports_callbacks(app):
    WIDGET_KEYS = ['b2b', 'vc_it', 'shpd', 'qlik']

    @app.callback(
        Output('reports-autoupdate-interval', 'disabled'),
        Input('reports-autoupdate', 'value'),
    )
    def _toggle_reports_autoupdate(enabled):
        return not bool(enabled)

    @app.callback(
        [Output(f'reports-widget-{k}', 'style') for k in WIDGET_KEYS],
        Input('reports-widget-selector', 'value'),
        prevent_initial_call=False
    )
    def toggle_reports_widgets(selected):
        selected = selected or []
        return [{'display': 'block' if k in selected else 'none'} for k in WIDGET_KEYS]

    @app.callback(
        Output('reports-time-range', 'data'),
        Output('reports-export-pdf', 'href'),
        Output('reports-export-pdf-alt', 'href'),
        Input('reports-time-q-1h', 'n_clicks'),
        Input('reports-time-q-24h', 'n_clicks'),
        Input('reports-time-q-7d', 'n_clicks'),
        Input('reports-time-update', 'n_clicks'),
        Input('reports-autoupdate-interval', 'n_intervals'),
        Input('reports-widget-selector', 'value'),
        State('reports-time-start', 'value'),
        State('reports-time-end', 'value'),
        prevent_initial_call=False
    )
    def update_reports_time_range(q1h, q24h, q7d, q_update, n_interval, widgets, start_text, end_text):
        st, en = reports_resolve_time(callback_context)
        if st is None and en is None:
            # normalize 'YYYY-MM-DDTHH:MM:SS' -> 'YYYY-MM-DD HH:MM:SS' (datetime-local)
            if start_text and 'T' in start_text:
                start_text = start_text.replace('T', ' ')
            if end_text and 'T' in end_text:
                end_text = end_text.replace('T', ' ')
            # parse user-provided range or fall back to default.
            # Browser may omit seconds (e.g. 'YYYY-MM-DD HH:MM') when they are :00,
            # so try both formats before falling back.
            def _parse_dt(text):
                if not text:
                    return None
                for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
                    try:
                        return datetime.strptime(text, fmt)
                    except ValueError:
                        continue
                return None
            st = _parse_dt(start_text)
            if st is None:
                en_def = get_last_thursday_at_9am()
                st = en_def - timedelta(days=7)
            en = _parse_dt(end_text)
            if en is None:
                en_def = get_last_thursday_at_9am()
                en = en_def
        start_iso = st.strftime('%Y-%m-%dT%H:%M:%S')
        end_iso = en.strftime('%Y-%m-%dT%H:%M:%S')
        start_str = st.strftime('%Y-%m-%d %H:%M:%S')
        end_str = en.strftime('%Y-%m-%d %H:%M:%S')
        data = {
            'start_iso': start_iso,
            'end_iso': end_iso,
            'start_str': start_str,
            'end_str': end_str,
        }
        pdf_widgets = [w for w in (widgets or []) if w != 'extra']
        if not pdf_widgets:
            pdf_widgets = [k for k in WIDGET_KEYS if k != 'extra']
        widgets_param = ','.join(pdf_widgets)
        href = f"{app.get_relative_path('/export-pdf')}?start={start_iso}&end={end_iso}&widgets={widgets_param}"
        href_alt = f"{app.get_relative_path('/export-pdf-alt')}?start={start_iso}&end={end_iso}&widgets={widgets_param}"
        return data, href, href_alt

    @app.callback(
        Output('vc-it-summary', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_vc_it_summary(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']

        vc_it_elk = get_vc_it_elk_summary(start, end)
        vc_it_genie = get_vc_it_genie_summary(start_iso, end_iso)

        if vc_it_genie['biggest_attack_by_bps']:
            vc_it_genie['biggest_attack_by_bps']['max_bps'] = c_rounding(vc_it_genie['biggest_attack_by_bps']['max_bps'], 'bps')
            vc_it_genie['biggest_attack_by_bps']['max_pps'] = c_rounding(vc_it_genie['biggest_attack_by_bps']['max_pps'], 'pps')
        else:
            vc_it_genie['biggest_attack_by_bps'] = 'N/A'
            
        if vc_it_genie['longest_attack_by_duration']:
            vc_it_genie['longest_attack_by_duration']['max_bps'] = c_rounding(vc_it_genie['longest_attack_by_duration']['max_bps'], 'bps')
            vc_it_genie['longest_attack_by_duration']['max_pps'] = c_rounding(vc_it_genie['longest_attack_by_duration']['max_pps'], 'pps')
            vc_it_genie['longest_attack_by_duration']['duration'] = sec_to_str(vc_it_genie['longest_attack_by_duration']['duration'])
        else:
            vc_it_genie['longest_attack_by_duration'] = 'N/A'

        children = [
            html.Div(f"{start}  ->  {end}", className='time-range-label'),
            html.Div('drop/challenge AND packet_count >= 1000000', className='section-subtitle'),
            dict_to_kv_html(vc_it_elk),
            html.Div('vc-it/IT_pe', className='section-subtitle'),
            dict_to_kv_html(vc_it_genie),
        ]
        return html.Div(children)

    @app.callback(
        Output('vc-it-stats', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_vc_it_stats(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']
        stats = get_vc_it_extra_stats(start_iso, end_iso)
        return _build_stats_children(stats, time_range_str=f"{start}  ->  {end}")

    @app.callback(
        Output('b2b-summary', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_b2b_summary(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']

        b2b = get_b2b_summary(start_iso, end_iso)
        if b2b['biggest_attack_by_bps']:
            b2b['biggest_attack_by_bps']['max_bps'] = c_rounding(b2b['biggest_attack_by_bps']['max_bps'], 'bps')
            b2b['biggest_attack_by_bps']['max_pps'] = c_rounding(b2b['biggest_attack_by_bps']['max_pps'], 'pps')
        else:
            b2b['biggest_attack_by_bps'] = 'N/A'
        if b2b['longest_attack_by_duration']:
            b2b['longest_attack_by_duration']['max_bps'] = c_rounding(b2b['longest_attack_by_duration']['max_bps'], 'bps')
            b2b['longest_attack_by_duration']['max_pps'] = c_rounding(b2b['longest_attack_by_duration']['max_pps'], 'pps')
            b2b['longest_attack_by_duration']['duration'] = sec_to_str(b2b['longest_attack_by_duration']['duration'])
        else:
            b2b['longest_attack_by_duration'] = 'N/A'

        b2b_display = {k: v for k, v in b2b.items()
                       if k not in ('total_genie_events', 'vc_it_it_pe_events',
                                    'test_events', 'fttb_events', 'total_b2b_events')}

        children = [
            html.Div(f"{start}  ->  {end}", className='time-range-label'),
            html.Div('For biggest/longest: (NOT Home/Non-Home/vc-it/IT_pe/FTTB/test) --(AND >1 Gbps AND >5 min)--', className='section-subtitle'),
            dict_to_kv_html(b2b_display),
        ]
        return html.Div(children)

    @app.callback(
        Output('b2b-totals', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_b2b_totals(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']

        b2b = get_b2b_summary(start_iso, end_iso)
        totals = {
            'total_genie_events': b2b['total_genie_events'],
            'vc_it_it_pe_events': b2b['vc_it_it_pe_events'],
            'test_events': b2b['test_events'],
            'fttb_events': b2b['fttb_events'],
            'total_b2b_events': b2b['total_b2b_events'],
        }
        return build_summary_display(start, end, None, totals)

    @app.callback(
        Output('shpd-summary', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_shpd_summary(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']

        shpd = get_shpd_genie_summary(start_iso, end_iso)
        if shpd['biggest_attack_by_bps']:
            shpd['biggest_attack_by_bps']['max_bps'] = c_rounding(shpd['biggest_attack_by_bps']['max_bps'], 'bps')
            shpd['biggest_attack_by_bps']['max_pps'] = c_rounding(shpd['biggest_attack_by_bps']['max_pps'], 'pps')
        else:
            shpd['biggest_attack_by_bps'] = 'N/A'
        if shpd['longest_attack_by_duration']:
            shpd['longest_attack_by_duration']['max_bps'] = c_rounding(shpd['longest_attack_by_duration']['max_bps'], 'bps')
            shpd['longest_attack_by_duration']['max_pps'] = c_rounding(shpd['longest_attack_by_duration']['max_pps'], 'pps')
            shpd['longest_attack_by_duration']['duration'] = sec_to_str(shpd['longest_attack_by_duration']['duration'])
        else:
            shpd['longest_attack_by_duration'] = 'N/A'

        children = [
            html.Div(f"{start}  ->  {end}", className='time-range-label'),
            html.Div('FTTB', className='section-subtitle'),
            dict_to_kv_html(shpd),
        ]
        return html.Div(children)

    @app.callback(
        Output('b2b-stats', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_b2b_stats(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']
        stats = get_b2b_extra_stats(start_iso, end_iso)
        return _build_stats_children(stats, time_range_str=f"{start}  ->  {end}")

    @app.callback(
        Output('shpd-stats', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_shpd_stats(time_range):
        start_iso = time_range['start_iso']
        end_iso = time_range['end_iso']
        start = time_range['start_str']
        end = time_range['end_str']
        stats = get_shpd_extra_stats(start_iso, end_iso)
        return _build_stats_children(stats, time_range_str=f"{start}  ->  {end}")

    @app.callback(
        Output('qlik-summary', 'children'),
        Input('reports-time-range', 'data'),
        prevent_initial_call=False
    )
    def update_qlik_summary(time_range):
        start = time_range['start_str']
        end = time_range['end_str']

        radware_top = get_top_radware_summary(start, end)
        items = []
        for i in radware_top:
            if i['key'] != '0.0.0.0':
                resolved = resolve_ip(i['key'])
                items.append(html.Div([
                    html.Span(i['key'], className='kv-key'),
                    html.Span(f"{resolved} ({i['doc_count']})", className='kv-value')
                ], className='kv-row'))

        children = [
            html.Div(f"{start}  ->  {end}", className='time-range-label'),
            html.Div(items) if items else html.Div('No data', className='kv-value'),
        ]
        return html.Div(children)


def create_reports_app(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.CYBORG, '/static/styles.css'],
               external_scripts=['/static/ag_grid_custom_filters.js'])

    app.layout = reports_layout()
    register_reports_callbacks(app)

    export_route = url_base_pathname + 'export-pdf'

    @server.route(export_route)
    def reports_export_pdf():
        start = request.args.get('start')
        end = request.args.get('end')
        if not start or not end:
            en = get_last_thursday_at_9am()
            st = en - timedelta(days=7)
            start = st.strftime('%Y-%m-%dT%H:%M:%S')
            end = en.strftime('%Y-%m-%dT%H:%M:%S')
        widgets_param = request.args.get('widgets', '')
        widgets = [w for w in widgets_param.split(',') if w] if widgets_param else None
        try:
            pdf_bytes = build_reports_pdf(start, end, widgets=widgets)
        except Exception as e:
            return Response(f"PDF generation failed: {e}", status=500, mimetype='text/plain')

        filename = f"ddos_report_{start.replace(':', '-').replace(' ', '_')}_{end.replace(':', '-').replace(' ', '_')}.pdf"
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    export_route_alt = url_base_pathname + 'export-pdf-alt'

    @server.route(export_route_alt)
    def reports_export_pdf_alt():
        start = request.args.get('start')
        end = request.args.get('end')
        if not start or not end:
            en = get_last_thursday_at_9am()
            st = en - timedelta(days=7)
            start = st.strftime('%Y-%m-%dT%H:%M:%S')
            end = en.strftime('%Y-%m-%dT%H:%M:%S')
        widgets_param = request.args.get('widgets', '')
        widgets = [w for w in widgets_param.split(',') if w] if widgets_param else None
        try:
            pdf_bytes = build_reports_pdf_alt(start, end, widgets=widgets)
        except Exception as e:
            return Response(f"PDF generation failed: {e}", status=500, mimetype='text/plain')

        filename = f"ddos_report_alt_{start.replace(':', '-').replace(' ', '_')}_{end.replace(':', '-').replace(' ', '_')}.pdf"
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    return app

