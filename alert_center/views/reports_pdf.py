import os
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

from services.utils import c_rounding, sec_to_str, resolve_ip, hist_pct
from services.data_fetcher import (
    get_vc_it_elk_summary,
    get_vc_it_genie_summary,
    get_b2b_summary,
    get_shpd_genie_summary,
    get_top_radware_summary,
    get_vc_it_extra_stats,
    get_b2b_extra_stats,
    get_shpd_extra_stats,
)
from alert_center.views.theme import STYLE


# --------------------------------------------------------------------------- #
# Dark theme palette — sourced from alert_center.views.theme.STYLE so that the
# PDF export stays cohesive with the Dash views. reportlab needs HexColor
# objects, so we wrap the shared hex strings here.
# --------------------------------------------------------------------------- #
BG_PAGE     = colors.HexColor(STYLE['bg_page'])
BG_FRAME    = colors.HexColor(STYLE['bg_frame'])
BG_HEADER   = colors.HexColor(STYLE['bg_header'])
BG_ROW_ODD  = colors.HexColor(STYLE['bg_row_odd'])
BG_ROW_EVEN = colors.HexColor(STYLE['bg_row_even'])
GRID_COLOR  = colors.HexColor(STYLE['chart_grid'])
TEXT_MAIN   = colors.HexColor(STYLE['text_main'])
TEXT_MUTED  = colors.HexColor(STYLE['text_muted'])

# Active accents (teal pair) used for the BPS / Duration histograms.
ACCENT_BPS      = colors.HexColor(STYLE['accent_bps'])
ACCENT_DURATION = colors.HexColor(STYLE['accent_duration'])

# Legacy aliases, kept for backwards compatibility / future use.
ACCENT_CYAN = colors.HexColor(STYLE['accent_cyan'])
ACCENT_ORANGE = colors.HexColor(STYLE['accent_orange'])
ACCENT_BLUE   = colors.HexColor(STYLE['accent_blue'])


# --------------------------------------------------------------------------- #
# Translation map: technical keys -> Russian labels.
# Tokens like B2B, BPS, PPS, FTTB, vc-it, IT_pe, drop/challenge kept verbatim.
# --------------------------------------------------------------------------- #
KEY_RU = {
    # B2B totals
    'total_genie_events': 'Всего событий genie',
    'vc_it_it_pe_events': 'События ВК-ИТ / IT_pe',
    'test_events': 'Тестовые события',
    'fttb_events': 'События FTTB',
    'total_b2b_events': 'Всего событий B2B',
    # attack record fields
    'id': 'ID',
    'max_bps': 'Макс. BPS',
    'max_pps': 'Макс. PPS',
    'start_time': 'Начало атаки',
    'end_time': 'Конец атаки',
    'resource': 'Ресурс',
    'target': 'Цель',
    'duration': 'Длительность',
    # descriptive stats
    'avg_bps': 'Средний BPS',
    'median_bps': 'Медиана BPS',
    'stddev_bps': 'Отклонение BPS',
    'avg_duration': 'Средняя длительность',
    'median_duration': 'Медиана длительности',
    'stddev_duration': 'Отклонение длительности',
}

# Static UI strings
STR_TIME_RANGE = 'Период'
STR_SUMMARY = 'Сводка'
STR_DESCRIPTIVE_STATS = 'Описательная статистика'
STR_BPS_DIST = 'Распределение BPS'
STR_DURATION_DIST = 'Распределение длительности'
STR_NO_DATA = 'Нет данных'
STR_BIN = 'Диапазон'
STR_PCT_TOTAL = '% от общего'
STR_HOSTNAME_COUNT = 'Имя хоста (кол-во)'
STR_BIGGEST_BPS = 'Крупнейшая атака по BPS'
STR_LONGEST_DURATION = 'Длиннейшая атака'


def _humanize_key(key):
    """Translate a (possibly dotted) key into Russian, preserving unknown tail."""
    if key in KEY_RU:
        return KEY_RU[key]
    # try last segment after the dot (e.g. biggest_attack_by_bps.max_bps -> max_bps)
    tail = key.split('.')[-1]
    if tail in KEY_RU:
        return KEY_RU[tail]
    return key


_FONT_REGISTERED = False


def _ensure_cyrillic_font():
    global _FONT_REGISTERED
    if _FONT_REGISTERED:
        return
    project_root = os.path.join(os.path.dirname(__file__), '..', '..')
    candidates = [
        os.path.join(project_root, 'static', 'fonts', 'DejaVuSans.ttf'),
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/liberation/LiberationSans-Regular.ttf',
        '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path:
        pdfmetrics.registerFont(TTFont('Cyrillic', path))
        bold_candidates = [
            os.path.join(project_root, 'static', 'fonts', 'DejaVuSans-Bold.ttf'),
            '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
            '/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf',
            '/usr/share/fonts/liberation/LiberationSans-Bold.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
        ]
        bold_path = next((p for p in bold_candidates if os.path.exists(p)), None)
        if bold_path:
            pdfmetrics.registerFont(TTFont('Cyrillic-Bold', bold_path))
        else:
            pdfmetrics.registerFont(TTFont('Cyrillic-Bold', path))
    _FONT_REGISTERED = True


def _cyr_styles():
    _ensure_cyrillic_font()
    base = getSampleStyleSheet()
    registered = pdfmetrics.getRegisteredFontNames()
    font_name = 'Cyrillic' if 'Cyrillic' in registered else 'Helvetica'
    bold_name = 'Cyrillic-Bold' if 'Cyrillic-Bold' in registered else (
        'Helvetica-Bold' if 'Helvetica-Bold' in registered else font_name
    )
    return {
        'Heading1': ParagraphStyle('CyrH1', parent=base['Heading1'],
                                   fontName=bold_name, fontSize=18,
                                   textColor=ACCENT_CYAN, spaceAfter=6),
        'Heading3': ParagraphStyle('CyrH3', parent=base['Heading3'],
                                   fontName=bold_name, fontSize=12,
                                   textColor=ACCENT_CYAN, spaceAfter=4),
        'Normal': ParagraphStyle('CyrN', parent=base['Normal'],
                                fontName=font_name, fontSize=10,
                                textColor=TEXT_MAIN),
        'Muted': ParagraphStyle('CyrMuted', parent=base['Normal'],
                                fontName=font_name, fontSize=9,
                                textColor=TEXT_MUTED),
        'Subtitle': ParagraphStyle('CyrSub', parent=base['Normal'],
                                    fontName=font_name, fontSize=9,
                                    textColor=ACCENT_CYAN, spaceAfter=4),
    }


def _on_page(canv, doc):
    """Paint a dark background on every page before flowables are drawn."""
    canv.saveState()
    canv.setFillColor(BG_PAGE)
    canv.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canv.restoreState()


# --------------------------------------------------------------------------- #
# Table builders
# --------------------------------------------------------------------------- #
def _kv_cell_style(font_name):
    return ParagraphStyle(
        'kv_cell', fontName=font_name, fontSize=9, leading=11, textColor=TEXT_MAIN,
    )


def _to_paragraph(value, font_name, cell_style):
    """Wrap a value in a Paragraph, escaping HTML and preserving newlines."""
    if isinstance(value, str) and '\n' in value:
        html = '<br/>'.join(_escape_html(ln) for ln in value.split('\n'))
    else:
        html = _escape_html(value)
    return Paragraph(html, cell_style)


def _kv_table(rows, font_name, colWidths=(220, 280)):
    """rows: list of [key, value]. Renders a dark-themed two-column table.

    Keys are translated via _humanize_key. Strings with newlines are wrapped in
    Paragraph so they break correctly."""
    cell_style = _kv_cell_style(font_name)
    data = []
    for k, v in rows:
        label = _humanize_key(k)
        data.append([_to_paragraph(label, font_name, cell_style), _to_paragraph(v, font_name, cell_style)])

    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_ROW_EVEN),
        ('GRID', (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ])
    for i in range(len(data)):
        bg = BG_ROW_ODD if i % 2 == 1 else BG_ROW_EVEN
        style.add('BACKGROUND', (0, i), (-1, i), bg)

    tbl = Table(data, colWidths=list(colWidths))
    tbl.setStyle(style)
    return tbl


def _titled_header_table(title, rows, font_name, colWidths=(220, 280)):
    """Two-column table with a coloured title header row, then key/value rows.

    Used for the split biggest/longest attack tables: the title row spans both
    columns so the table name appears once instead of repeated in every row.
    """
    cell_style = _kv_cell_style(font_name)
    hdr_style = ParagraphStyle(
        'titled_hdr', fontName=font_name + '-Bold' if (font_name + '-Bold') in pdfmetrics.getRegisteredFontNames() else font_name,
        fontSize=10, leading=12, textColor=TEXT_MAIN, alignment=1,
    )

    data = [[Paragraph(title, hdr_style), '']]
    for k, v in rows:
        label = _humanize_key(k)
        data.append([_to_paragraph(label, font_name, cell_style), _to_paragraph(v, font_name, cell_style)])

    style = TableStyle([
        ('SPAN', (0, 0), (-1, 0)),
        ('BACKGROUND', (0, 0), (-1, 0), BG_HEADER),
        ('BACKGROUND', (0, 1), (-1, -1), BG_ROW_EVEN),
        ('GRID', (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ])
    for i in range(1, len(data)):
        bg = BG_ROW_ODD if (i - 1) % 2 == 1 else BG_ROW_EVEN
        style.add('BACKGROUND', (0, i), (-1, i), bg)

    tbl = Table(data, colWidths=list(colWidths))
    tbl.setStyle(style)
    return tbl


def _grid_table(header, rows, font_name, colWidths):
    """Generic dark-themed grid table with a header row (used for histograms/top)."""
    cell_style = _kv_cell_style(font_name)
    hdr_style = ParagraphStyle(
        'grid_hdr', fontName=font_name + '-Bold' if (font_name + '-Bold') in pdfmetrics.getRegisteredFontNames() else font_name,
        fontSize=9, leading=11, textColor=TEXT_MAIN,
    )
    data = [[Paragraph(str(h), hdr_style) for h in header]]
    for r in rows:
        data.append([_to_paragraph(c, font_name, cell_style) for c in r])

    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_HEADER),
        ('GRID', (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ])
    for i in range(1, len(data)):
        bg = BG_ROW_ODD if (i - 1) % 2 == 1 else BG_ROW_EVEN
        style.add('BACKGROUND', (0, i), (-1, i), bg)

    tbl = Table(data, colWidths=list(colWidths))
    tbl.setStyle(style)
    return tbl


def _escape_html(s):
    return (str(s).replace('&', '&amp;').replace('<', '&lt;')
            .replace('>', '&gt;').replace('"', '&quot;'))


# --------------------------------------------------------------------------- #
# Page builder
# --------------------------------------------------------------------------- #
def _split_summary(summary):
    """Pull biggest_attack_by_bps / longest_attack_by_duration out of a summary
    dict and return (rest, biggest, longest) for separate table rendering."""
    if not isinstance(summary, dict):
        return summary, None, None
    rest = {k: v for k, v in summary.items()
            if k not in ('biggest_attack_by_bps', 'longest_attack_by_duration')}
    biggest = summary.get('biggest_attack_by_bps')
    longest = summary.get('longest_attack_by_duration')
    return rest, biggest, longest


def _flatten_simple(d):
    """Flatten a non-nested dict to [(key, value)] preserving insertion order."""
    if not isinstance(d, dict):
        return [(STR_SUMMARY, str(d))]
    return [(k, v) for k, v in d.items()]


def _build_pdf_page(story, styles, title, time_range_str, summary_dicts,
                    stats=None, extra_subtitles=None,
                    show_summary_title=True, show_attack_records=True):
    """Append one category's content to the reportlab story."""
    _ensure_cyrillic_font()
    font_name = 'Cyrillic' if 'Cyrillic' in pdfmetrics.getRegisteredFontNames() else 'Helvetica'

    story.append(Paragraph(title, styles['Heading1']))
    story.append(Paragraph(f"{STR_TIME_RANGE}: {time_range_str}", styles['Muted']))
    story.append(Spacer(1, 12))

    subtitles = extra_subtitles or []
    subtitle_idx = 0
    for summary in summary_dicts:
        if subtitle_idx < len(subtitles):
            story.append(Paragraph(subtitles[subtitle_idx], styles['Subtitle']))
            subtitle_idx += 1

        rest, biggest, longest = _split_summary(summary)

        # main summary table (translated keys)
        if isinstance(rest, dict) and rest:
            if show_summary_title:
                story.append(Paragraph(STR_SUMMARY, styles['Heading3']))
            story.append(_kv_table(_flatten_simple(rest), font_name))
            story.append(Spacer(1, 10))
        elif not isinstance(rest, dict):
            if show_summary_title:
                story.append(Paragraph(f"{STR_SUMMARY}: {rest}", styles['Normal']))
            else:
                story.append(Paragraph(str(rest), styles['Normal']))
            story.append(Spacer(1, 10))

        # split attack tables
        if show_attack_records:
            had_biggest = isinstance(summary, dict) and 'biggest_attack_by_bps' in summary
            had_longest = isinstance(summary, dict) and 'longest_attack_by_duration' in summary
            if isinstance(biggest, dict) and biggest:
                story.append(_titled_header_table(
                    STR_BIGGEST_BPS, _flatten_simple(biggest), font_name))
                story.append(Spacer(1, 10))
            elif biggest is None and had_biggest:
                story.append(_titled_header_table(
                    STR_BIGGEST_BPS, [(STR_NO_DATA, '')], font_name))
                story.append(Spacer(1, 10))

            if isinstance(longest, dict) and longest:
                story.append(_titled_header_table(
                    STR_LONGEST_DURATION, _flatten_simple(longest), font_name))
                story.append(Spacer(1, 10))
            elif longest is None and had_longest:
                story.append(_titled_header_table(
                    STR_LONGEST_DURATION, [(STR_NO_DATA, '')], font_name))
                story.append(Spacer(1, 10))

    if stats is not None:
        story.append(Paragraph(STR_DESCRIPTIVE_STATS, styles['Heading3']))
        story.append(Spacer(1, 4))
        if stats.get('avg_bps') is None:
            story.append(Paragraph(STR_NO_DATA, styles['Normal']))
            story.append(Spacer(1, 12))
        else:
            stats_display = {
                'avg_bps': c_rounding(stats['avg_bps'], 'bps'),
                'median_bps': c_rounding(stats['median_bps'], 'bps'),
                'stddev_bps': c_rounding(stats['stddev_bps'], 'bps') if stats['stddev_bps'] else 'N/A',
                'avg_duration': sec_to_str(stats['avg_duration']),
                'median_duration': sec_to_str(stats['median_duration']),
                'stddev_duration': sec_to_str(round(stats['stddev_duration'])) if stats['stddev_duration'] else 'N/A',
            }
            story.append(_kv_table(_flatten_simple(stats_display), font_name))
            story.append(Spacer(1, 12))

        def _hist_drawing(bins, bar_color):
            labels = [b.get('label', '') for b in bins]
            values = [hist_pct(b) for b in bins]
            n = len(labels)
            width = 500
            height = 180
            drawing = Drawing(width, height)
            # dark canvas backdrop for the chart area
            from reportlab.graphics.shapes import Rect
            drawing.add(Rect(0, 0, width, height, fillColor=BG_FRAME,
                             strokeColor=None))
            chart = VerticalBarChart()
            chart.x = 50
            chart.y = 30
            chart.width = width - 70
            chart.height = height - 55
            chart.data = [values]
            chart.bars[0].fillColor = bar_color
            chart.bars[0].strokeColor = bar_color
            chart.barWidth = max(2, (chart.width / max(n, 1)) * 0.6)
            chart.groupSpacing = 4
            chart.valueAxis.valueMin = 0
            chart.valueAxis.valueMax = max(values) * 1.15 if values else 1
            chart.valueAxis.valueStep = max(1, round((chart.valueAxis.valueMax) / 5))
            chart.valueAxis.valueMin = 0
            chart.valueAxis.labelTextFormat = '%d%%'
            chart.valueAxis.labels.fontName = font_name
            chart.valueAxis.labels.fontSize = 7
            chart.valueAxis.labels.fillColor = TEXT_MUTED
            chart.valueAxis.strokeColor = GRID_COLOR
            chart.valueAxis.gridStrokeColor = GRID_COLOR
            chart.categoryAxis.categoryNames = labels
            chart.categoryAxis.labels.fontName = font_name
            chart.categoryAxis.labels.fontSize = 7
            chart.categoryAxis.labels.fillColor = TEXT_MUTED
            chart.categoryAxis.labels.angle = 45
            chart.categoryAxis.labels.boxAnchor = 'ne'
            chart.categoryAxis.labels.dy = -2
            chart.categoryAxis.strokeColor = GRID_COLOR
            drawing.add(chart)
            return drawing

        if stats.get('bps_histogram'):
            story.append(Paragraph(STR_BPS_DIST, styles['Heading3']))
            story.append(Spacer(1, 4))
            rows = [[b.get('label', ''), f"{hist_pct(b)}%"] for b in stats['bps_histogram']]
            story.append(_grid_table([STR_BIN, STR_PCT_TOTAL], rows, font_name,
                                     colWidths=[220, 280]))
            story.append(Spacer(1, 4))
            story.append(_hist_drawing(stats['bps_histogram'], ACCENT_BPS))
            story.append(Spacer(1, 12))

        if stats.get('duration_histogram'):
            story.append(Paragraph(STR_DURATION_DIST, styles['Heading3']))
            story.append(Spacer(1, 4))
            rows = [[b.get('label', ''), f"{hist_pct(b)}%"] for b in stats['duration_histogram']]
            story.append(_grid_table([STR_BIN, STR_PCT_TOTAL], rows, font_name,
                                     colWidths=[220, 280]))
            story.append(Spacer(1, 4))
            story.append(_hist_drawing(stats['duration_histogram'], ACCENT_DURATION))
            story.append(Spacer(1, 12))


# --------------------------------------------------------------------------- #
# Top-level PDF builder
# --------------------------------------------------------------------------- #
def build_reports_pdf(start_iso, end_iso, widgets=None):
    """Build the multi-page reports PDF and return its bytes."""
    PDF_WIDGET_KEYS = ['b2b', 'vc_it', 'shpd', 'qlik']
    if widgets is None:
        widgets = PDF_WIDGET_KEYS
    else:
        widgets = [w for w in widgets if w in PDF_WIDGET_KEYS]
        if not widgets:
            widgets = PDF_WIDGET_KEYS

    start_str = start_iso.replace('T', ' ')
    end_str = end_iso.replace('T', ' ')
    time_range_str = f"{start_str}  ->  {end_str}"

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            topMargin=40, bottomMargin=40,
                            leftMargin=40, rightMargin=40)
    styles = _cyr_styles()
    story = []

    b2b_totals_keys = ('total_genie_events', 'vc_it_it_pe_events',
                       'test_events', 'fttb_events', 'total_b2b_events')

    # ---- Always-on first page: Итоги (B2B totals) ----
    b2b_full = get_b2b_summary(start_iso, end_iso)
    '''if b2b_full.get('biggest_attack_by_bps'):
        b2b_full['biggest_attack_by_bps']['max_bps'] = c_rounding(b2b_full['biggest_attack_by_bps']['max_bps'], 'bps')
        b2b_full['biggest_attack_by_bps']['max_pps'] = c_rounding(b2b_full['biggest_attack_by_bps']['max_pps'], 'pps')
    if b2b_full.get('longest_attack_by_duration'):
        b2b_full['longest_attack_by_duration']['max_bps'] = c_rounding(b2b_full['longest_attack_by_duration']['max_bps'], 'bps')
        b2b_full['longest_attack_by_duration']['max_pps'] = c_rounding(b2b_full['longest_attack_by_duration']['max_pps'], 'pps')
        b2b_full['longest_attack_by_duration']['duration'] = sec_to_str(b2b_full['longest_attack_by_duration']['duration'])
    '''
    totals = {k: b2b_full[k] for k in b2b_totals_keys}

    _build_pdf_page(story, styles, "Итоги", time_range_str,
                    summary_dicts=[totals],
                    show_summary_title=False, show_attack_records=False)
    story.append(PageBreak())

    # ---- Page 1: B2B ----
    if 'b2b' in widgets:
        b2b_rest = {k: v for k, v in b2b_full.items() if k not in b2b_totals_keys}
        b2b_stats = get_b2b_extra_stats(start_iso, end_iso)
        _build_pdf_page(story, styles, "Отчёт: B2B", time_range_str,
                        summary_dicts=[b2b_rest], stats=b2b_stats,
                        extra_subtitles=[
                            "Для крупнейшей/длиннейшей: (НЕ Home/Non-Home/vc-it/IT_pe/FTTB/test) --(И >1 Gbps И >5 мин)--"
                        ])
        if len(widgets) > 1:
            story.append(PageBreak())

    # ---- Page 2: ВК ИТ ----
    if 'vc_it' in widgets:
        vc_it_elk = get_vc_it_elk_summary(start_str, end_str)
        vc_it_genie = get_vc_it_genie_summary(start_iso, end_iso)
        if vc_it_genie.get('biggest_attack_by_bps'):
            vc_it_genie['biggest_attack_by_bps']['max_bps'] = c_rounding(vc_it_genie['biggest_attack_by_bps']['max_bps'], 'bps')
            vc_it_genie['biggest_attack_by_bps']['max_pps'] = c_rounding(vc_it_genie['biggest_attack_by_bps']['max_pps'], 'pps')
        if vc_it_genie.get('longest_attack_by_duration'):
            vc_it_genie['longest_attack_by_duration']['max_bps'] = c_rounding(vc_it_genie['longest_attack_by_duration']['max_bps'], 'bps')
            vc_it_genie['longest_attack_by_duration']['max_pps'] = c_rounding(vc_it_genie['longest_attack_by_duration']['max_pps'], 'pps')
            vc_it_genie['longest_attack_by_duration']['duration'] = sec_to_str(vc_it_genie['longest_attack_by_duration']['duration'])
        vc_it_stats = get_vc_it_extra_stats(start_iso, end_iso)
        _build_pdf_page(story, styles, "Отчёт: ВК ИТ", time_range_str,
                        summary_dicts=[vc_it_elk, vc_it_genie], stats=vc_it_stats,
                        extra_subtitles=["drop/challenge И packet_count >= 1000000", "vc-it/IT_pe"])
        if widgets.index('vc_it') < len(widgets) - 1:
            story.append(PageBreak())

    # ---- Page 3: ШПД ----
    if 'shpd' in widgets:
        shpd = get_shpd_genie_summary(start_iso, end_iso)
        if shpd.get('biggest_attack_by_bps'):
            shpd['biggest_attack_by_bps']['max_bps'] = c_rounding(shpd['biggest_attack_by_bps']['max_bps'], 'bps')
            shpd['biggest_attack_by_bps']['max_pps'] = c_rounding(shpd['biggest_attack_by_bps']['max_pps'], 'pps')
        if shpd.get('longest_attack_by_duration'):
            shpd['longest_attack_by_duration']['max_bps'] = c_rounding(shpd['longest_attack_by_duration']['max_bps'], 'bps')
            shpd['longest_attack_by_duration']['max_pps'] = c_rounding(shpd['longest_attack_by_duration']['max_pps'], 'pps')
            shpd['longest_attack_by_duration']['duration'] = sec_to_str(shpd['longest_attack_by_duration']['duration'])
        shpd_stats = get_shpd_extra_stats(start_iso, end_iso)
        _build_pdf_page(story, styles, "Отчёт: ШПД", time_range_str,
                        summary_dicts=[shpd], stats=shpd_stats,
                        extra_subtitles=["FTTB"])
        if widgets.index('shpd') < len(widgets) - 1:
            story.append(PageBreak())

    # ---- Page 4: ТОП атакуемых ресурсов ВК ----
    if 'qlik' in widgets:
        _ensure_cyrillic_font()
        font_name = 'Cyrillic' if 'Cyrillic' in pdfmetrics.getRegisteredFontNames() else 'Helvetica'
        story.append(Paragraph("ТОП атакуемых ресурсов ВК", styles['Heading1']))
        story.append(Paragraph(f"{STR_TIME_RANGE}: {time_range_str}", styles['Muted']))
        story.append(Spacer(1, 12))

        radware_top = get_top_radware_summary(start_str, end_str)
        top_rows = []
        for bucket in radware_top:
            ip = bucket.get('key')
            count = bucket.get('doc_count', 0)
            if ip == '0.0.0.0':
                continue
            resolved = resolve_ip(ip)
            top_rows.append([ip, f"{resolved} ({count})"])

        if top_rows:
            story.append(_grid_table(["IP", STR_HOSTNAME_COUNT], top_rows, font_name,
                                     colWidths=[160, 340]))
        else:
            story.append(Paragraph(STR_NO_DATA, styles['Normal']))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

