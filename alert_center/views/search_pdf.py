import ipaddress
from io import BytesIO
from datetime import datetime

import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle

from services.data_fetcher import (
    get_alerts_for_search,
    get_genie_events_for_search,
    get_dp_data,
    waf_blocks_by_net,
    get_top_attack_sources,
)
from services.utils import c_rounding
from alert_center.views.reports_pdf import (
    _cyr_styles,
    _on_page,
    _grid_table,
    _kv_table,
    _ensure_cyrillic_font,
    STR_NO_DATA,
    STR_TIME_RANGE,
)
from alert_center.views.reports_pdf_alt import (
    _build_top_sources_widget,
    _build_top_countries_widget,
    _fetch_top_source_countries,
)
from reportlab.pdfbase import pdfmetrics


SEARCH_PDF_WIDGET_KEYS = ['alerts', 'genie', 'dp', 'waf', 'sources']


def _range_to_cidr(start_ip, end_ip):
    """Collapse a [start_ip, end_ip] integer range into a single CIDR string.

    Mirrors the inline helper in search_interactive.py::load_search_genie so the
    'Target CIDR' column in the PDF matches the on-page ag-grid rendering.
    """
    s = ipaddress.IPv4Address(start_ip)
    e = ipaddress.IPv4Address(end_ip)
    total = int(e) - int(s) + 1
    prefix = 32 - (total.bit_length() - 1)
    return str(ipaddress.IPv4Network(f"{s}/{prefix}", strict=False))


def _normalize_iso(s):
    """Accept either 'YYYY-MM-DDTHH:MM:SS' or 'YYYY-MM-DD HH:MM:SS' and return
    the space-separated form used by ClickHouse / SQLite / display."""
    if not s:
        return ''
    return s.replace('T', ' ')


def _fmt_bps(value):
    if value is None or value == '' or (isinstance(value, float) and pd.isna(value)):
        return ''
    try:
        return c_rounding(value, 'bps')
    except (TypeError, ValueError):
        return str(value)


def _fmt_pps(value):
    if value is None or value == '' or (isinstance(value, float) and pd.isna(value)):
        return ''
    try:
        return c_rounding(value, 'pps')
    except (TypeError, ValueError):
        return str(value)


def _strip_uid_markdown(value):
    """The on-page alerts table renders alert_uid as '[uid](/alert/uid)' so the
    ag-grid markdown cellRenderer shows a clickable link. For the PDF we want
    plain text — strip the markdown wrapper if present."""
    if not isinstance(value, str):
        return str(value) if value is not None else ''
    v = value.strip()
    if v.startswith('[') and '](' in v:
        try:
            return v[1:v.index('](')]
        except ValueError:
            return v
    return v


def _section_header(story, styles, title):
    story.append(Paragraph(title, styles['Heading3']))
    story.append(Spacer(1, 4))


def _build_alerts_section(story, styles, font_name, cidr, start, end):
    _section_header(story, styles, "Алерты")
    try:
        df = get_alerts_for_search(cidr, start, end)
    except Exception as e:
        story.append(Paragraph(f"Ошибка: {e}", styles['Normal']))
        story.append(Spacer(1, 12))
        return

    if df is None or df.empty:
        story.append(Paragraph(STR_NO_DATA, styles['Normal']))
        story.append(Spacer(1, 12))
        return

    header = ['UID', 'Уровень', 'CIDR', 'Начало', 'Конец', 'Макс. BPS']
    rows = []
    for _, r in df.iterrows():
        end_val = '' if pd.isna(r.get('end_time')) else str(r.get('end_time') or '')
        rows.append([
            _strip_uid_markdown(r.get('alert_uid')),
            str(r.get('level', '')),
            str(r.get('target_cidr', '')),
            str(r.get('start_time', '')),
            end_val,
            _fmt_bps(r.get('max_bps')),
        ])
    story.append(_grid_table(header, rows, font_name,
                             colWidths=[100, 50, 85, 100, 100, 80]))
    story.append(Spacer(1, 12))


def _build_genie_section(story, styles, font_name, cidr, start, end):
    _section_header(story, styles, "Связанные события Genie")
    try:
        df = get_genie_events_for_search(cidr, start, end)
    except Exception as e:
        story.append(Paragraph(f"Ошибка: {e}", styles['Normal']))
        story.append(Spacer(1, 12))
        return

    if df is None or df.empty:
        story.append(Paragraph(STR_NO_DATA, styles['Normal']))
        story.append(Spacer(1, 12))
        return

    # Row prep mirrors search_interactive.py::load_search_genie (lines 320-338)
    # so the columns line up exactly with the on-page ag-grid table.
    df = df.copy()
    df['resource'] = df['resource'].apply(lambda x: str(x))
    df['last_update'] = pd.to_datetime(df['last_update']).dt.strftime('%Y-%m-%d %H:%M:%S')
    df['start'] = df['start'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, datetime) else str(x))
    df['end'] = df['end'].apply(
        lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, datetime) and len(str(x)) > 5 else ''
    )
    df['target_network'] = df['target_network'].apply(lambda x: str(x))
    df['target_broadcast'] = df['target_broadcast'].apply(lambda x: str(x))
    df['max_bps'] = df['max_bps'].apply(lambda x: x if x else 0)
    df['max_pps'] = df['max_pps'].apply(lambda x: x if x else 0)
    df['Target CIDR'] = df.apply(
        lambda r: _range_to_cidr(r['target_network'], r['target_broadcast']), axis=1
    )

    header = ['ID', 'Target CIDR', 'Начало', 'Конец', 'Макс. BPS',
              'Макс. PPS', 'Ресурс', 'Статус', 'Последнее обновление']
    rows = []
    for _, r in df.iterrows():
        rows.append([
            str(r.get('id', '')),
            str(r.get('Target CIDR', '')),
            str(r.get('start', '')),
            str(r.get('end', '')),
            _fmt_bps(r.get('max_bps')),
            _fmt_pps(r.get('max_pps')),
            str(r.get('resource', '')),
            str(r.get('status', '')),
            str(r.get('last_update', '')),
        ])
    story.append(_grid_table(header, rows, font_name,
                             colWidths=[30, 65, 70, 70, 55, 55, 60, 45, 65]))
    story.append(Spacer(1, 12))


def _build_dp_section(story, styles, font_name, cidr, start, end):
    _section_header(story, styles, "DP (Radware/AntiDDoS)")
    try:
        dp_data = get_dp_data(cidr, start, end, top_descriptions_num=10)
    except Exception as e:
        story.append(Paragraph(f"Ошибка: {e}", styles['Normal']))
        story.append(Spacer(1, 12))
        return

    if not isinstance(dp_data, dict) \
       or 'aggregations' not in dp_data \
       or 'top_descriptions' not in dp_data['aggregations']:
        story.append(Paragraph(STR_NO_DATA, styles['Normal']))
        story.append(Spacer(1, 12))
        return

    agg = dp_data['aggregations']
    drops = agg.get('drops', {}).get('drop_packets', {}).get('value', 0)
    buckets = agg.get('top_descriptions', {}).get('buckets', [])

    if buckets:
        desc_lines = "\n".join(
            f"{item.get('key', '')}: {int(item.get('total_packets', {}).get('value', 0))} pkts"
            for item in buckets
        )
    else:
        desc_lines = STR_NO_DATA

    rows = [
        ['Drops', f"{int(drops)} pkts"],
        ['Top drop descriptions', desc_lines],
    ]
    story.append(_kv_table(rows, font_name, colWidths=(150, 365)))
    story.append(Spacer(1, 12))


def _build_waf_section(story, styles, font_name, cidr, start, end):
    _section_header(story, styles, "WAF")
    try:
        res = waf_blocks_by_net(cidr, start, end, timeout=60)
    except Exception as e:
        story.append(Paragraph(f"Ошибка: {e}", styles['Normal']))
        story.append(Spacer(1, 12))
        return

    buckets = []
    if isinstance(res, dict) and 'aggregations' in res \
       and 'pass_block' in res['aggregations']:
        buckets = res['aggregations']['pass_block'].get('buckets', [])

    if not buckets:
        story.append(Paragraph(STR_NO_DATA, styles['Normal']))
        story.append(Spacer(1, 12))
        return

    header = ['Decision', 'Count']
    rows = [[b.get('key', ''), str(b.get('doc_count', 0))] for b in buckets]
    story.append(_grid_table(header, rows, font_name, colWidths=[250, 265]))
    story.append(Spacer(1, 12))


def _build_sources_section(story, styles, font_name, cidr, start, end):
    """Pie charts mirroring search_interactive.py::load_search_sources —
    Source IPs and Source Countries, each rendered as a list-with-color-
    swatches + pie widget (reports_pdf_alt style), stacked vertically."""
    _section_header(story, styles, "Топ источников атак")
    try:
        buckets = get_top_attack_sources(start, end, cidr=cidr or None, size=11)
    except Exception as e:
        story.append(Paragraph(f"Ошибка: {e}", styles['Normal']))
        story.append(Spacer(1, 12))
        return

    # filter 0.0.0.0 and zero counts (mirrors _build_pie_drawing /
    # load_search_sources)
    filtered = [(b.get('key'), b.get('doc_count', 0)) for b in (buckets or [])
                if b.get('key') != '0.0.0.0' and b.get('doc_count', 0)]
    if not filtered:
        story.append(Paragraph(STR_NO_DATA, styles['Normal']))
        story.append(Spacer(1, 12))
        return

    # Source IPs widget — reuse the reports layout (legend list + pie).
    ip_buckets = [{'key': ip, 'doc_count': c} for ip, c in filtered]
    story.append(Paragraph("Source IPs", styles['Normal']))
    story.append(Spacer(1, 4))
    story.append(_build_top_sources_widget(ip_buckets, font_name, styles))
    story.append(Spacer(1, 16))

    # Country aggregation via reports_pdf_alt._fetch_top_source_countries.
    country_bins = _fetch_top_source_countries(start, end, cidr=cidr or None, size=10)
    story.append(Paragraph("Source Countries", styles['Normal']))
    story.append(Spacer(1, 4))
    if country_bins:
        story.append(_build_top_countries_widget(country_bins, font_name, styles))
    else:
        story.append(Paragraph(STR_NO_DATA, styles['Normal']))
    story.append(Spacer(1, 12))


def build_search_pdf(start, end, cidr=None, widgets=None):
    """Build a multi-section PDF mirroring the on-page Search view.

    `start` / `end` may be either 'YYYY-MM-DDTHH:MM:SS' (from the URL built by
    update_search_export_href) or 'YYYY-MM-DD HH:MM:SS' (from get_last_thursday_at_9am
    fallback in the Flask route). Both are normalized to the space-separated form.

    `widgets` is a list of widget keys from SEARCH_PDF_WIDGET_KEYS. None or
    empty -> all five sections are emitted.
    """
    # Widget selection — defensive filtering mirrors build_reports_pdf.
    if widgets is None:
        widgets = list(SEARCH_PDF_WIDGET_KEYS)
    else:
        widgets = [w for w in widgets if w in SEARCH_PDF_WIDGET_KEYS]
        if not widgets:
            widgets = list(SEARCH_PDF_WIDGET_KEYS)

    start_str = _normalize_iso(start)
    end_str = _normalize_iso(end)
    time_range_str = f"{start_str}  ->  {end_str}"

    _ensure_cyrillic_font()
    font_name = 'Cyrillic' if 'Cyrillic' in pdfmetrics.getRegisteredFontNames() else 'Helvetica'

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                           topMargin=40, bottomMargin=40,
                           leftMargin=40, rightMargin=40)
    styles = _cyr_styles()
    story = []

    # ---- Header ----
    story.append(Paragraph("Поиск по CIDR", styles['Heading1']))
    story.append(Paragraph(f"{STR_TIME_RANGE}: {time_range_str}", styles['Muted']))
    if cidr:
        story.append(Paragraph(f"CIDR: {cidr}", styles['Muted']))
    story.append(Spacer(1, 12))

    # ---- CIDR validation (mirrors render_search_error / _validate_cidr) ----
    if not cidr:
        story.append(Paragraph("Не указан CIDR для поиска.", styles['Normal']))
        doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
        return buffer.getvalue()

    try:
        ipaddress.IPv4Network(cidr, strict=False)
    except Exception as e:
        story.append(Paragraph(f"Некорректный CIDR &quot;{cidr}&quot;: {e}", styles['Normal']))
        doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
        return buffer.getvalue()

    # ---- Sections, in the canonical widget order ----
    section_builders = {
        'alerts':  _build_alerts_section,
        'genie':   _build_genie_section,
        'dp':      _build_dp_section,
        'waf':     _build_waf_section,
        'sources': _build_sources_section,
    }
    ordered_widgets = [w for w in SEARCH_PDF_WIDGET_KEYS if w in widgets]

    for i, w in enumerate(ordered_widgets):
        section_builders[w](story, styles, font_name, cidr, start_str, end_str)
        if i < len(ordered_widgets) - 1:
            story.append(PageBreak())

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buffer.getvalue()

