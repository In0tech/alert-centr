"""PDF export for the Metrics page.

Produces a single A4 page summarising the eight left-column KPI widgets
shown on /dashapp/metrics_dashapp/. Excludes the Level 1 & 2 alerts count
widget, the Manual counter card, and the Constants card (per spec).

Reuses the reportlab theme/font/table helpers from reports_pdf.py so the
visual style matches the rest of the PDF exports (light GitHub palette
sourced from alert_center.views.theme).

Public entrypoint: build_metrics_pdf(start_iso, end_iso) -> bytes
"""

from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

from alert_center.views.reports_pdf import (
    _ensure_cyrillic_font,
    _cyr_styles,
    _on_page,
    BG_FRAME,
    BG_HEADER,
    BG_ROW_ODD,
    BG_ROW_EVEN,
    GRID_COLOR,
    TEXT_MAIN,
    TEXT_MUTED,
    ACCENT_CYAN,
)
from alert_center.views.metrics_interactive import (
    _get_metrics_values,
    _fmt,
    _pct,
    BANDWIDTH_BPS,
    EXERCISES_SCALE,
)


# --------------------------------------------------------------------------- #
# Widget definitions — title, formula subtitle, and a renderer that mirrors
# the on-screen formatting in metrics_interactive.update_kpi_widgets().
# Each renderer takes the values dict from _get_metrics_values() and returns
# a string (may contain newlines).
# --------------------------------------------------------------------------- #
def _render_coverage(v):
    return (f"({_fmt(v['services_monitored'])}/{_fmt(v['critical_total'])}) "
            f"{_pct(v['services_monitored'], v['critical_total'])}")


def _render_auto(v):
    return (f"({_fmt(v['level_1_2_alerts'])}/{_fmt(v['genie_events'])}) "
            f"{_pct(v['level_1_2_alerts'], v['genie_events'])}")


def _render_mitigated(v):
    return (f"({_fmt(v['attacks_no_degradation'])}/{_fmt(v['confirmed_attacks'])}) "
            f"{_pct(v['attacks_no_degradation'], v['confirmed_attacks'])}")


def _render_manual(v):
    return (f"({_fmt(v['manual_handled'])}/{_fmt(v['confirmed_attacks'])}) "
            f"{_pct(v['manual_handled'], v['confirmed_attacks'])}")


def _render_capacity(v):
    max_bps = v['max_bps']
    if max_bps is None:
        return '?'
    gbps = max_bps / 1_000_000_000
    pct = max_bps / BANDWIDTH_BPS * 100
    return f"({gbps:.1f} Gbps / 480 Gbps) = {pct:.1f}%"


def _render_baseline(v):
    return (f"({_fmt(v['services_with_baseline'])}/{_fmt(v['critical_total'])}) "
            f"{_pct(v['services_with_baseline'], v['critical_total'])}")


def _render_postmortem(v):
    return (f"({_fmt(v['manual_debrief'])}/{_fmt(v['confirmed_attacks'])}) "
            f"{_pct(v['manual_debrief'], v['confirmed_attacks'])}")


def _render_exercises(v):
    selected = v['exercises_level']
    label = next((lbl for lvl, lbl in EXERCISES_SCALE if lvl == selected), '')
    return label if label else f"{selected}."


# Ordered list of (title, formula, renderer) for the 8 KPI widgets.
WIDGETS = [
    ('Покрытие мониторингом защищаемых сервисов',
     '(число сервисов с активным мониторингом / общее число критичных сервисов) × 100%',
     _render_coverage),
    ('Доля подтверждённых атак из обнаруженных автоматически',
     '(все подтвержденные атаки / атаки, выявленные автоматически) × 100%',
     _render_auto),
    ('Доля атак, успешно смягченных без влияния на бизнес',
     '((все подтвержденные атаки − Инциденты, завершенные дебрифом) / все подтвержденные атаки) × 100%',
     _render_mitigated),
    ('Доля инцидентов с ручным вмешательством',
     '(инциденты с ручным вмешательством / все подтвержденные атаки) × 100%',
     _render_manual),
    ('Достаточность capacity / headroom',
     '(max bps of the biggest alert for the period / 480 Gbps) × 100%',
     _render_capacity),
    ('Доля сервисов с заранее определённым профилем нормального трафика',
     '(сервисы с актуальным baseline / все критичные сервисы) × 100%',
     _render_baseline),
    ('Доля инцидентов с postmortem / PIR',
     '(Инциденты, завершенные дебрифом / lvl 1 & 2 alert) × 100%',
     _render_postmortem),
    ('Регулярность учений и тестов',
     'номер по шкале 1..5',
     _render_exercises),
]


# --------------------------------------------------------------------------- #
# Table builder — one row per KPI widget: title | formula | value.
# Mirrors the dark/light themed tables in reports_pdf._kv_table but with
# three columns and a header row.
# --------------------------------------------------------------------------- #
def _widget_table(rows, styles):
    """rows: list of (title, formula, value_str). Returns a styled Table."""
    _ensure_cyrillic_font()
    font_name = styles['Normal'].fontName
    bold_name = styles['Heading3'].fontName

    title_style = ParagraphStyle(
        'widget_title', fontName=bold_name, fontSize=9, leading=11,
        textColor=TEXT_MAIN,
    )
    formula_style = ParagraphStyle(
        'widget_formula', fontName=font_name, fontSize=8, leading=10,
        textColor=TEXT_MUTED,
    )
    value_style = ParagraphStyle(
        'widget_value', fontName=bold_name, fontSize=10, leading=12,
        textColor=ACCENT_CYAN,
    )
    hdr_style = ParagraphStyle(
        'widget_hdr', fontName=bold_name, fontSize=9, leading=11,
        textColor=TEXT_MAIN, alignment=1,
    )

    data = [[
        Paragraph('Метрика', hdr_style),
        Paragraph('Формула', hdr_style),
        Paragraph('Значение', hdr_style),
    ]]
    for title, formula, value in rows:
        # Escape & preserve newlines for multi-line values (e.g. exercises).
        def _esc(s):
            return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;').replace('\n', '<br/>'))
        data.append([
            Paragraph(_esc(title), title_style),
            Paragraph(_esc(formula), formula_style),
            Paragraph(_esc(value), value_style),
        ])

    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BG_HEADER),
        ('GRID', (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ])
    for i in range(1, len(data)):
        bg = BG_ROW_ODD if (i - 1) % 2 == 1 else BG_ROW_EVEN
        style.add('BACKGROUND', (0, i), (-1, i), bg)

    tbl = Table(data, colWidths=[150, 220, 130])
    tbl.setStyle(style)
    return tbl


# --------------------------------------------------------------------------- #
# Top-level builder
# --------------------------------------------------------------------------- #
def build_metrics_pdf(start_iso, end_iso):
    """Build the metrics KPI PDF and return its bytes.

    Parameters
    ----------
    start_iso, end_iso : str
        'YYYY-MM-DDTHH:MM:SS' bounds (datetime-local format, same as the
        metrics Dash app's time-range store).
    """
    _ensure_cyrillic_font()
    styles = _cyr_styles()

    # Normalise the ISO bounds to the 'YYYY-MM-DD HH:MM:SS' form expected
    # by the metrics helpers (matches what the Dash app stores in
    # metrics-time-range.start_str / end_str).
    def _to_str(iso):
        if not iso:
            return ''
        return iso.replace('T', ' ') if 'T' in iso else iso

    start_str = _to_str(start_iso)
    end_str = _to_str(end_iso)

    vals = _get_metrics_values(start_str, end_str)

    rows = [(title, formula, renderer(vals))
            for title, formula, renderer in WIDGETS]

    # --- Build the story ----------------------------------------------------
    story = []
    story.append(Paragraph('Метрики', styles['Heading1']))
    story.append(Paragraph(f"Период: {start_str}  →  {end_str}", styles['Muted']))
    story.append(Spacer(1, 10))
    story.append(_widget_table(rows, styles))

    # --- Render to a BytesIO buffer ----------------------------------------
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36,
        title='Метрики', author='Alert Center ADDOS',
    )
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()

