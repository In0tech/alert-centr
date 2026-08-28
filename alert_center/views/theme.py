# --------------------------------------------------------------------------- #
# ALTERNATE LIGHT THEME — square, monospace, GitHub-style light palette.
#
# Standalone alternative to theme.py. Swap in by importing from theme_alt
# instead of theme in a view, e.g.:
#
#     from alert_center.views.theme_alt import (
#         STYLE, grid_ag_theme, genie_columnDefs, alerts_columnDefs,
#     )
#
# and pointing external_stylesheets at '/static/styles_alt.css'.
#
# All values are raw hex strings (or ints) so that both consumers
# (Dash/Plotly in reports_interactive.py and reportlab in reports_pdf.py)
# can import this module without pulling in any extra dependencies.
# --------------------------------------------------------------------------- #

STYLE = {
    # backgrounds / surfaces
    'bg_page':        '#f4f5f7',
    'bg_frame':       '#ffffff',
    'bg_header':       '#eceff3',
    'bg_row_odd':     '#ffffff',
    'bg_row_even':    '#f6f8fa',

    # text
    'text_main':      '#1f2328',
    'text_muted':     '#57606a',

    # chart canvas / grid
    'chart_paper_bg':  '#ffffff',
    'chart_plot_bg':   '#ffffff',
    'chart_grid':      '#e3e6ea',
    'chart_font_size': 10,

    # accents — blue pair (active, used for BPS / Duration histograms)
    'accent_bps':       '#0969da',
    'accent_duration':  '#0550ae',


    'accent_cyan':      '#1d939c',
    'accent_green':     '#1f883d',

    # legacy aliases (kept for backwards compatibility / future use)
    'accent_yellow': '#bf8700',
    'accent_orange': '#bc4c00',
    'accent_blue':   '#0969da',
}


# --------------------------------------------------------------------------- #
# PIE_COLORS — palette for pie chart slices, shared across:
#   - alert_center/views/search_interactive.py (Plotly pies)
#   - alert_center/views/reports_pdf_alt.py     (reportlab pies, wrapped in
#                                                colors.HexColor at import)
# Plain hex strings so theme.py stays dependency-free.
#
# GitHub Primer categorical palette — hues/tones aligned with STYLE accents
# (#0969da, #1d939c, #bf8700, #bc4c00) so pies blend with the rest of the UI.
# --------------------------------------------------------------------------- #
PIE_COLORS = [
    '#0969da',  # blue   (matches accent_bps)
    '#bf8700',  # amber  (matches accent_yellow)
    '#1f883d',  # green
    '#bc4c00',  # orange (matches accent_orange)
    '#8250df',  # purple
    '#1d939c',  # teal   (matches accent_cyan)
    '#d1242f',  # red
    '#6e7781',  # gray
    '#339ea9',  # light teal
    '#a371f7',  # light purple
    '#fb8f44',  # light orange
    '#2da44e',  # light green
    '#d4a72c',  # light amber
    '#218bff',  # light blue
    '#8c959f',  # light gray
]





##### ag_grid_settings

genie_columnDefs = [
    {"field": "id", "filter": "agTextColumnFilter", 'maxWidth': 90},
    {"field": "Target CIDR", "filter": "agTextColumnFilter", 'maxWidth': 160},
    {"field": "start", "filter": "agTextColumnFilter", 'maxWidth': 160},
    {"field": "end", "filter": "agTextColumnFilter", 'maxWidth': 160},
    {"field": "max_bps", "filter": "agNumberColumnFilter", 'maxWidth': 120,
        "valueFormatter": {"function":
    "Math.abs(Number(params.value) || 0) >= 1e9 ? (Number(params.value)/1e9).toFixed(2) + ' Gbps' : (Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + ' Mbps' : (Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + ' kbps' : (Number(params.value) || 0) + ' bps'))"
                    }},

    {"field": "max_pps", "filter": "agNumberColumnFilter", 'maxWidth': 120,
        "valueFormatter": {"function":
    "Math.abs(Number(params.value) || 0) >= 1e9 ? (Number(params.value)/1e9).toFixed(2) + ' Gpps' : (Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + ' Mpps' : (Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + ' kpps' : (Number(params.value) || 0) + ' pps'))"
                    }},

    {"field": "resource", "filter": "agTextColumnFilter"},

    {"field": "status", "filter": "agTextColumnFilter", 'maxWidth': 100},

    {"field": "last_update", "filter": "agTextColumnFilter", "maxWidth": 160},
]


alerts_columnDefs = [
    {"field": "alert_uid", "filter": "agTextColumnFilter", "cellRenderer": "markdown",
         "cellStyle": { "cursor": "pointer", "textDecoration": "underline", "color": "#0969da" },
          "linkTarget":"_blank"
},

    {"field": "level", "filter": "agNumberColumnFilter", 'maxWidth': 100, 'headerName': 'Level'},
    {"field": "target_cidr", "filter": "agTextColumnFilter"},
    {"field": "start_time", "filter": "agTextColumnFilter"},
    {"field": "end_time", "sort": "desc", "filter": "agTextColumnFilter"},

    {"field": "max_bps",  "filter": "agNumberColumnFilter", 'headerName': 'Max BPS',
        "valueFormatter": {"function":
"Math.abs(Number(params.value) || 0) >= 1e9 ? (Number(params.value)/1e9).toFixed(2) + ' Gbps' : (Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + ' Mbps' : (Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + ' kbps' : (Number(params.value) || 0) + ' bps'))"
                    }},

    {"field": "waf_blocks", "filter": "agNumberColumnFilter", 'headerName': 'WAF Blocks', 'maxWidth': 160,
        "valueFormatter": {"function":
"params.value == null ? '' :  ( (Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + 'M' : (Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + 'k' : (Number(params.value) || 0)))) + ' (' + Number(params.data.waf_blocks_per_sec).toFixed(2) + '/s)'"                    }},

    {"field": "dp_blocks", "filter": "agNumberColumnFilter", 'headerName': 'DP Blocks', 'maxWidth': 160,
        "valueFormatter": {"function":
"params.value == null ? '' :  ( (Math.abs(Number(params.value) || 0) >= 1e6 ? (Number(params.value)/1e6).toFixed(2) + 'M' : (Math.abs(Number(params.value) || 0) >= 1000 ? (Number(params.value)/1000).toFixed(2) + 'k' : (Number(params.value) || 0)))) + ' (' + Number(params.data.dp_blocks_per_sec).toFixed(2) + '/s)'"
                    }},
]

#     {"field": "start_time", "filter": "DateRangeFilter", "filterParams": {"buttons": ["reset"]}},
#    {"field": "end_time", "sort": "desc", "filter": "DateRangeFilter", "filterParams": {"buttons": ["reset"]}},


mitigations_columnDefs = [
    {"field": "CIDR", "filter": "agTextColumnFilter"},
    {"field": "Mitigation", "filter": "agTextColumnFilter"},
    {"field": "Update time", "filter": "agTextColumnFilter"},
]

mitigations_history_columnDefs = [
    {"field": "Changed at", "filter": "agTextColumnFilter", "sort": "desc", 'maxWidth': 180},
    {"field": "CIDR", "filter": "agTextColumnFilter"},
    {"field": "Mitigation", "filter": "agTextColumnFilter"},
]

grid_ag_theme = {"function":
"""themeQuartz.withParams({
        backgroundColor: "#ffffff",
        browserColorScheme: "light",
        chromeBackgroundColor: {
            ref: "foregroundColor",
            mix: 0.07,
            onto: "backgroundColor"
        },
        fontFamily: {
            googleFont: "Roboto"
        },
        foregroundColor: "#1f2328",
        headerBackgroundColor: "#eceff3",
        headerFontSize: 13,
        headerFontWeight: 600,
        headerTextColor: "#57606a",
        borderColor: "#d0d4da",
        rowHoverColor: "#f4f5f7",
        oddRowBackgroundColor: "#f6f8fa",
        spacing: 6,
        wrapperBorderRadius: 0
    })"""}

