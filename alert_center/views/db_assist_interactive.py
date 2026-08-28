import configparser
import json
import os
import urllib3
import datetime
import dash_bootstrap_components as dbc
import requests
from dash import Dash, dcc, html, Input, Output, State
from dash.exceptions import PreventUpdate

from services.data_fetcher import opensearch_client

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Config (alert_center.conf)
# ---------------------------------------------------------------------------
_config = configparser.ConfigParser()
_config.read(os.path.join(os.path.dirname(__file__), '..', '..', 'alert_center.conf'))

_AI_API_URL = _config.get('AI_API', 'URL')
_AI_API_KEY = _config.get('AI_API', 'KEY')
_AI_MODEL = _config.get('AI_API', 'MODEL')


# Selected index patterns only — the runner ignores any other pattern the AI
# may have produced.
INDEX_PATTERNS = {
    'dp':  '*radwarevision*,*antiddos*',
    'waf': '*ru.solidwaf*',
}

INDEX_SCHEMAS = {
    'dp': (
        "Индексы: *radwarevision*,*antiddos* (Radware Vision / AntiDDoS DefensePro).\n"
        "События — syslog-сообщения от DefensePro, прокинутые через logstash в OpenSearch.\n"
        "Известные поля:\n"
        "  Время:\n"
        "    @timestamp (date — основное поле для time-фильтров и сортировки; .keyword не нужен);\n"
        "    time (text — syslog-строка 'DD-MM-YYYY HH:MM:SS'; для term/aggs/sort используй time.keyword).\n"
        "  Событие:\n"
        "    event_id (text — UUID; .keyword; связывает связанные между собой start/term события);\n"
        "    state (text — .keyword; значения 'sampled', 'start', 'term');\n"
        "    type (text — всегда 'syslog'; .keyword);\n"
        "    level (text — .keyword; значения 'WARNING', ...);\n"
        "    severity (text — .keyword; типовые значения 'high', 'low', 'medium');\n"
        "    action (text — .keyword; типовые значения 'drop', 'forward');\n"
        "    attack_type (text — .keyword; значения 'Regular', ...);\n"
        "    category (text — .keyword; типовые значения 'Access', 'Traffic-Filters', 'GeoFeed', 'Anomalies', 'ConnectionPPS');\n"
        "    description (text — .keyword; ВАЖНО: значение хранится с обрамляющими двойными\n"
        "                 кавычками, например '\"Blocklist\"', '\"Geolocation Permanent\"'.\n"
        "                 Term-фильтр должен включать кавычки: {\"term\": {\"description.keyword\": \"\\\"Blocklist\\\"\"}});\n"
        "    policy (text — .keyword; ВАЖНО: значение хранится с обрамляющими двойными кавычками,\n"
        "            например '\"block_not_used_ports_vpn\"'. Типовые значения: '\"ns-gldn-net-global\"',\n"
        "            '\"bee-yaroslavl\"', '\"www-beeline-ru\"', '\"P2P_block_router_tcp\"',\n"
        "            '\"P2P_DMVPNhub_block_tcp\"'. Term-фильтр должен включать кавычки.);\n"
        "    message (text — оригинальный syslog; для term/aggs используй message.keyword).\n"
        "  Адреса/порты:\n"
        "    ipsrc (ip — .keyword);\n"
        "    ipdst (ip — .keyword);\n"
        "    host.ip (ip — ВЛОЖЕННОЕ поле; используй host.ip.keyword внутри term/terms/sort/aggs);\n"
        "    sport (text — строка-порт; .keyword);\n"
        "    dport (text — строка-порт; .keyword).\n"
        "  Числа:\n"
        "    packet_count (long — числовое, .keyword не нужен);\n"
        "    volume (text — строка-байты; .keyword)."
    ),
    'waf': (
        "Индексы: *ru.solidwaf* (SolidWAF).\n"
        "Известные поля:\n"
        "  @timestamp (date — .keyword не нужен);\n"
        "  client_ip (ip — используй client_ip.keyword для term/terms/sort/aggs);\n"
        "  decision (text — используй decision.keyword; значения 'Pass'/'Block');\n"
        "  method (text — используй method.keyword);\n"
        "  path (text — используй path.keyword);\n"
        "  app (text — используй app.keyword);\n"
        "  geoip.country_name (text — используй geoip.country_name.keyword);\n"
        "  os (text — используй os.keyword);\n"
        "  backend (text — используй backend.keyword)."
    ),
}


# ---------------------------------------------------------------------------
# AI client
# ---------------------------------------------------------------------------
def call_ai(messages, model=None):
    """Call the internal Beeline AI chat completions endpoint.

    Returns the assistant text content. Raises on HTTP error.
    """
    headers = {
        'Authorization': f'Bearer {_AI_API_KEY}',
        'Content-Type': 'application/json',
    }
    payload = {
        'messages': messages,
        'model': model or _AI_MODEL,
        'stream': False,
    }
    resp = requests.post(_AI_API_URL, headers=headers, json=payload, verify=False, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    try:
        return data['choices'][0]['message']['content']
    except (KeyError, IndexError):
        return json.dumps(data, ensure_ascii=False)


def _strip_code_fences(text):
    """Extract a JSON object from text that may be wrapped in ```json ... ```."""
    s = text.strip()
    if s.startswith('```'):
        lines = s.splitlines()
        if lines[0].startswith('```'):
            lines = lines[1:]
        if lines and lines[-1].startswith('```'):
            lines = lines[:-1]
        s = '\n'.join(lines).strip()
    return s


def _build_system_prompt(index_type, mode):
    schema = INDEX_SCHEMAS.get(index_type, '')
    pattern = INDEX_PATTERNS.get(index_type, '')
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    base = (
        "Ты виртуальный ассистент в билайн. Твоя задача — помогать инженерам "
        "формировать OpenSearch-запросы для расследования DDoS/WAF инцидентов.\n\n"
        f"Сейчас {now}\n"
        f"Целевой индекс (выбран пользователем, не меняй его): {pattern}\n"
        f"{schema}\n\n"
        "Жёсткие правила:\n"
        "1. Возвращай ТОЛЬКО валидное JSON-тело OpenSearch-запроса "
        "(объект, который передаётся в параметр body метода opensearch_client.search). "
        "Пример: {\"size\": 0, \"query\": {\"bool\": {\"filter\": [{\"range\": "
        "{\"@timestamp\": {\"gte\": \"now-1h\", \"lte\": \"now\"}}}}]}}, "
        "\"aggs\": {...}}\n"
        "Пример агрегации (внимание: текстовые/ip поля всегда через .keyword): "
        "{\"size\": 0, \"query\": {\"bool\": {\"filter\": ["
        "{\"range\": {\"@timestamp\": {\"gte\": \"now-1h\", \"lte\": \"now\"}}}, "
        "{\"term\": {\"action.keyword\": \"drop\"}}]}}, "
        "\"aggs\": {\"top_ipdst\": {\"terms\": {\"field\": \"ipdst.keyword\", \"size\": 10}}}}\n"
        "2. НЕ включай поле index — индекс будет подставлен автоматически.\n"
        "3. НЕ оборачивай ответ в markdown-блоки (без ```), НЕ добавляй пояснений.\n"
        "4. Текстовые и ip-поля из схемы выше (любые поля с пометкой text или ip) "
        "НЕ поддерживают агрегации, сортировку и term/terms-фильтры напрямую — "
        "OpenSearch вернёт 400 'Text fields are not optimised...'. "
        "ВСЕГДА обращайся к ним через sub-field с суффиксом .keyword "
        "(например \"ipdst.keyword\", \"action.keyword\", \"host.ip.keyword\") "
        "внутри terms/term/sort/aggs. Числовые поля (long) и date-поля (@timestamp) "
        "в .keyword не нуждаются.\n"
        "5. Для сортировки по времени используй @timestamp (это date-поле, .keyword не нужен). "
        "Не сортируй и не агрегируй по текстовым полям без .keyword.\n"
        "6. ВАЖНО: поля description и policy хранятся с обрамляющими двойными "
        "кавычками внутри значения (например description='\"Blocklist\"', "
        "policy='\"ns-gldn-net-global\"'). Term-фильтр обязан включать эти кавычки: "
        "{\"term\": {\"policy.keyword\": \"\\\"ns-gldn-net-global\\\"\"}}. "
    )
    if mode == 'chat':
        base += (
            "\n\nРежим: CHAT. Ты можешь обсуждать задачу, задавать уточняющие вопросы, "
            "объяснять замысел. Когда пользователь явно просит сформировать/выдать "
            "запрос — верни ТОЛЬКО JSON-тело запроса без единого символа вне его."
        )
    else:
        base += (
            "\n\nРежим: IMMEDIATE. Не веди беседу. По любому запросу пользователя "
            "сразу верни ТОЛЬКО JSON-тело запроса. Никакого текста, кроме самого JSON."
        )
    return base


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------
def _card(header_icon, header_text, body, width=None):
    col_kwargs = {}
    if width:
        col_kwargs['md'] = width
    return dbc.Col(
        html.Div([
            html.Div([
                html.I(className=f'bi bi-{header_icon} me-2'),
                html.H4(header_text)
            ], className='card-section-header'),
            html.Div(body, className='card-section-body')
        ], className='card-section mb-3'),
        **col_kwargs
    )


def _chat_bubble(role, text):
    is_user = role == 'user'
    align = 'flex-end' if is_user else 'flex-start'
    if is_user:
        bg = 'var(--accent-blue)'
        color = '#ffffff'
        border = '1px solid var(--accent-blue)'
    else:
        bg = 'var(--bg-row-even)'
        color = 'var(--text-primary)'
        border = '1px solid var(--border-light)'
    return html.Div(
        html.Div(text, style={
            'background': bg,
            'color': color,
            'border': border,
            'padding': '8px 12px',
            'borderRadius': '12px',
            'maxWidth': '85%',
            'whiteSpace': 'pre-wrap',
            'wordBreak': 'break-word',
        }),
        style={'display': 'flex', 'justifyContent': align, 'marginBottom': '6px'},
    )


def db_assist_layout():
    return html.Div([
        dcc.Location(id='url'),

        dbc.Row([

            # ----------------- AI Assistant -----------------
            _card('chat-dots-fill', 'AI Assistant', [
                html.Div([
                    html.Div([
                        html.Label('Mode', style={'marginBottom': '2px', 'fontSize': '0.85em'}),
                        dcc.Dropdown(
                            id='ai-mode',
                            options=[
                                {'label': 'Immediate', 'value': 'immediate'},
                                {'label': 'Chat', 'value': 'chat'},
                            ],
                            value='immediate', clearable=False, style={'width': '100%'},
                        ),
                    ], style={'flex': '1'}),
                    html.Div([
                        html.Label('Index pattern', style={'marginBottom': '2px', 'fontSize': '0.85em'}),
                        dcc.Dropdown(
                            id='os-index-type',
                            options=[
                                {'label': 'DP (Radware/AntiDDoS)', 'value': 'dp'},
                                {'label': 'WAF (SolidWAF)', 'value': 'waf'},
                            ],
                            value='dp', clearable=False, style={'width': '100%'},
                        ),
                    ], style={'flex': '1', 'marginLeft': '8px'}),
                ], style={'display': 'flex', 'marginBottom': '8px'}),

                dcc.Store(id='ai-messages', data=[]),
                dcc.Store(id='ai-pending', data=None),

                html.Div(
                    id='ai-chat-history',
                    style={
                        'height': '340px',
                        'overflowY': 'auto',
                        'border': '1px solid var(--border-color)',
                        'borderRadius': '8px',
                        'padding': '8px',
                        'marginBottom': '8px',
                        'background': 'var(--bg-card)',
                    },
                ),
                html.Div(
                    html.Span(className='spinner-border spinner-border-sm',
                              style={'marginRight': '6px'}),
                    id='ai-chat-loading',
                    style={'display': 'none', 'marginBottom': '8px'},
                ),

                html.Div(id='ai-error',
                         style={'color': 'var(--accent-red)', 'marginBottom': '6px',
                                'fontSize': '0.9em'}),

                html.Div([
                    dcc.Input(id='ai-user-input', placeholder='Describe what you want to query...',
                              style={
                                  'flex': '1',
                                  'backgroundColor': 'var(--bg-secondary)',
                                  'color': 'var(--text-primary)',
                                  'border': '1px solid var(--border-color)',
                                  'borderRadius': 'var(--radius-sm)',
                                  'padding': '6px 10px',
                                  'fontFamily': 'var(--font-sans)',
                                  'fontSize': '13px',
                              }),
                    html.Button('Send', id='ai-send', className='btn btn-outline',
                                style={'marginLeft': '6px'}),
                ], style={'display': 'flex'}),
            ], width=6),

            # ----------------- OpenSearch Runner -----------------
            _card('search', 'OpenSearch Runner', [
                html.Div([
                    html.Label('Query body (JSON)', style={'fontSize': '0.85em'}),
                    dcc.Textarea(
                        id='os-query-body',
                        placeholder='{"size": 0, "query": {...}, "aggs": {...}}',
                        wrap='off',
                        style={
                            'width': '100%',
                            'height': '300px',
                            'fontFamily': 'var(--font-mono)',
                            'fontSize': '0.85em',
                            'backgroundColor': 'var(--bg-secondary)',
                            'color': 'var(--text-primary)',
                            'border': '1px solid var(--border-color)',
                            'borderRadius': 'var(--radius-sm)',
                            'padding': '8px',
                            'overflow': 'auto',
                            'resize': 'vertical',
                            'whiteSpace': 'pre',
                            'lineHeight': '1.5',
                        },
                    ),
                    html.Div(
                        html.Span(className='spinner-border spinner-border-sm',
                                  style={'marginRight': '6px'}),
                        id='os-query-loading',
                        style={'display': 'none', 'marginTop': '8px'},
                    ),
                ], style={'marginBottom': '8px'}),
                html.Div([
                    html.Button('Run', id='os-run', className='btn btn-primary'),
                    html.Span(id='os-target-label',
                              style={'marginLeft': '12px', 'color': 'var(--text-muted)',
                                     'fontSize': '0.85em'}),
                ], style={'display': 'flex', 'alignItems': 'center'}),
                html.Div(id='os-error',
                         style={'color': 'var(--accent-red)', 'marginTop': '8px',
                                'fontSize': '0.9em'}),
                dbc.Accordion(
                    [dbc.AccordionItem(
                        [dcc.Loading(
                            html.Pre(id='os-result', className='data-pre',
                                     style={'maxHeight': '400px', 'overflow': 'auto'}),
                            type='dot',
                        )],
                        title=html.Span('Raw OpenSearch response', style={
                            'color': 'var(--text-muted)',
                            'fontSize': '0.85em',
                            'fontWeight': '400',
                        }),
                        item_id='os-result-item',
                    )],
                    start_collapsed=True, active_item=None,
                    style={'marginTop': '8px'},
                ),
            ], width=6),

        ], className='mb-3'),

        # ----------------- AI interpretation (full width) -----------------
        dbc.Row([
            _card('robot', 'AI interpretation', [
                dcc.Store(id='os-interpret-pending', data=None),
                dcc.Loading(
                    dcc.Markdown(
                        id='ai-interpretation',
                        style={'color': 'var(--text-primary)',
                               'fontSize': '14px', 'lineHeight': '1.6',
                               'minHeight': '40px'},
                        dangerously_allow_html=False,
                    ),
                    type='dot',
                ),
            ], width=12),
        ], className='mb-3'),
    ], className='page-container')


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------
def register_db_assist_callbacks(app):

    @app.callback(
        Output('os-target-label', 'children'),
        Input('os-index-type', 'value'),
    )
    def update_target_label(index_type):
        pattern = INDEX_PATTERNS.get(index_type, '?')
        return f'→ index: {pattern}'

    @app.callback(
        Output('ai-error', 'children', allow_duplicate=True),
        Input('os-index-type', 'value'),
        prevent_initial_call=True,
    )
    def clear_error_on_index_change(_):
        return ''

    # --- on_send: instant UI feedback ---
    # Appends the user bubble (and a placeholder assistant bubble) immediately,
    # clears the input, and stashes the request context in `ai-pending` so the
    # second callback can perform the actual (slow) AI call.
    @app.callback(
        Output('ai-messages', 'data', allow_duplicate=True),
        Output('ai-error', 'children'),
        Output('ai-user-input', 'value'),
        Output('ai-pending', 'data'),
        Input('ai-send', 'n_clicks'),
        State('ai-user-input', 'value'),
        State('ai-mode', 'value'),
        State('os-index-type', 'value'),
        State('ai-messages', 'data'),
        State('ai-pending', 'data'),
        prevent_initial_call=True,
    )
    def on_send(n_clicks, user_text, mode, index_type, messages, pending):
        if not n_clicks:
            raise PreventUpdate
        # Don't stack requests: ignore Send while one is already in flight.
        if pending:
            raise PreventUpdate
        if not (user_text or '').strip():
            return messages, 'Enter a prompt first.', '', None

        prior = list(messages or [])
        # Append only the user bubble — the Loading element will indicate
        # work in progress, no placeholder assistant bubble.
        new_messages = prior + [{'role': 'user', 'content': user_text}]

        pending_state = {
            'user_text': user_text,
            'mode': mode,
            'index_type': index_type,
            'prior_messages': prior,
        }
        return new_messages, '', '', pending_state

    # --- toggle Loading spinners based on pending state ---
    @app.callback(
        Output('ai-chat-loading', 'style'),
        Output('os-query-loading', 'style'),
        Input('ai-pending', 'data'),
        State('ai-mode', 'value'),
    )
    def toggle_loading(pending, mode):
        shown = {'display': 'flex', 'alignItems': 'center', 'marginBottom': '8px'}
        shown_q = {'display': 'flex', 'alignItems': 'center', 'marginTop': '8px'}
        hidden = {'display': 'none'}
        if pending:
            if mode == 'chat':
                return shown, hidden
            return hidden, shown_q
        return hidden, hidden

    # --- on_pending: actual (slow) AI call ---
    # Triggered as soon as `ai-pending` becomes non-None. Calls the AI, then
    # appends the real result to chat (chat) or fills the query body (immediate).
    @app.callback(
        Output('ai-messages', 'data'),
        Output('os-query-body', 'value', allow_duplicate=True),
        Output('ai-error', 'children', allow_duplicate=True),
        Output('ai-pending', 'data', allow_duplicate=True),
        Input('ai-pending', 'data'),
        prevent_initial_call=True,
    )
    def on_pending(pending):
        if not pending:
            raise PreventUpdate

        user_text = pending['user_text']
        mode = pending['mode']
        index_type = pending['index_type']
        prior = list(pending.get('prior_messages') or [])

        system_prompt = _build_system_prompt(index_type, mode)
        payload = [{'role': 'system', 'content': system_prompt}]
        payload.extend(prior)
        payload.append({'role': 'user', 'content': user_text})

        try:
            reply = call_ai(payload)
        except Exception as e:
            # Keep the user bubble, surface error.
            return prior + [{'role': 'user', 'content': user_text}], None, \
                f'AI error: {e}', None

        if mode == 'immediate':
            body_text = _strip_code_fences(reply)
            try:
                parsed = json.loads(body_text)
            except Exception:
                # Not valid JSON: keep user bubble, surface error, dump raw.
                return prior + [{'role': 'user', 'content': user_text}], reply, \
                    'AI did not return valid JSON in immediate mode.', None
            pretty_body = json.dumps(parsed, indent=2, ensure_ascii=False)
            # Keep user bubble + add confirmation bubble; query → runner pane.
            new_messages = prior + [
                {'role': 'user', 'content': user_text},
                {'role': 'assistant', 'content': '[Query generated]'},
            ]
            return new_messages, pretty_body, '', None

        # chat mode — append real reply after the user bubble.
        new_messages = prior + [
            {'role': 'user', 'content': user_text},
            {'role': 'assistant', 'content': reply},
        ]
        return new_messages, None, '', None

    # --- clientside: disable Send while an AI request is in flight ---
    app.clientside_callback(
        """
        function(pending) {
            return pending != null;
        }
        """,
        Output('ai-send', 'disabled'),
        Input('ai-pending', 'data'),
    )

    @app.callback(
        Output('ai-chat-history', 'children'),
        Input('ai-messages', 'data'),
    )
    def render_chat_history(messages):
        if not messages:
            return html.Div(
                'No messages yet. Describe what you want to query and press Send.',
                style={'color': 'var(--text-muted)', 'fontStyle': 'italic',
                       'padding': '4px'},
            )
        return [_chat_bubble(m['role'], m['content']) for m in messages]

    @app.callback(
        Output('os-result', 'children'),
        Output('os-error', 'children'),
        Input('os-run', 'n_clicks'),
        State('os-query-body', 'value'),
        State('os-index-type', 'value'),
        prevent_initial_call=True,
    )
    def run_opensearch(n_clicks, body_text, index_type):
        if not n_clicks:
            raise PreventUpdate
        if not (body_text or '').strip():
            return '', 'Empty query body.'
        try:
            body = json.loads(body_text)
        except Exception as e:
            return '', f'Invalid JSON: {e}'

        # Force the index to the selected pattern — ignore anything else.
        index = INDEX_PATTERNS.get(index_type, '*')
        try:
            res = opensearch_client.search(index=index, body=body)
        except Exception as e:
            return '', f'OpenSearch error: {e}'

        pretty = json.dumps(res, indent=2, ensure_ascii=False, default=str)
        return pretty, ''

    # --- arm AI interpretation as soon as a raw OpenSearch result lands ---
    # Watches `os-result` (populated by run_opensearch above) and stashes a
    # small payload in `os-interpret-pending` so the next callback can do the
    # actual (slow) LLM call. Skipped on empty result or error.
    #
    # Also captures user intent for context: prefer the last user message in
    # the AI-assistant chat (the original natural-language request), fall back
    # to the raw query body if the AI assistant was never used (user pasted
    # the OpenSearch JSON directly).
    @app.callback(
        Output('os-interpret-pending', 'data'),
        Input('os-result', 'children'),
        State('os-error', 'children'),
        State('os-index-type', 'value'),
        State('ai-messages', 'data'),
        State('os-query-body', 'value'),
        prevent_initial_call=True,
    )
    def arm_interpretation(raw_result, os_error, index_type, ai_messages, os_query_body):
        if not raw_result:
            raise PreventUpdate
        if os_error:
            raise PreventUpdate

        user_intent = ''
        for msg in reversed(list(ai_messages or [])):
            if msg.get('role') == 'user':
                user_intent = msg.get('content', '')
                break
        if not user_intent:
            user_intent = os_query_body or ''

        return {
            'raw': raw_result,
            'index_type': index_type,
            'user_intent': user_intent,
        }

    # --- run the (slow) LLM interpretation call ---
    # Triggered as soon as `os-interpret-pending` becomes non-None. Sends the
    # raw JSON to the AI with a brief, laconic system prompt and writes the
    # assistant's summary into the full-width `ai-interpretation` widget.
    # If user intent is available (AI-assistant prompt or pasted query body),
    # it is included so the interpretation matches what the user was after.
    @app.callback(
        Output('ai-interpretation', 'children'),
        Output('os-interpret-pending', 'data', allow_duplicate=True),
        Input('os-interpret-pending', 'data'),
        prevent_initial_call=True,
    )
    def run_interpretation(pending):
        if not pending:
            raise PreventUpdate

        raw = pending['raw']
        index_type = pending.get('index_type', '')
        user_intent = pending.get('user_intent', '')
        pattern = INDEX_PATTERNS.get(index_type, '?')

        system_prompt = (
            "Ты аналитик инцидентов сети/DDoS/WAF. Часто есть много фоновых блокировок"
            " 0.0.0.0 - весь интернет. Дан сырой JSON-ответ OpenSearch "
            f"(индекс: {pattern}). Кратко и лаконично выдели главное (3–6 "
            "буллетов): что это за данные, объём (total/число агрегаций), "
            "ключевые значения топов, заметные аномалии. "
            "Если указан исходный запрос пользователя, учитывай его при "
            "интерпретации (что он хотел узнать) — отвечай в контексте этого "
            "запроса. Если указан исходный запрос пользователя - самая главная"
            " задача - это ответить как можно лучше на его запрос."
        )
        if user_intent:
            user_content = (
                f"Исходный запрос пользователя:\n{user_intent}\n\n"
                f"Сырой ответ OpenSearch:\n{raw}"
            )
        else:
            user_content = f"Сырой ответ OpenSearch:\n{raw}"
        messages = [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_content},
        ]
        try:
            reply = call_ai(messages)
        except Exception as e:
            return f'**AI error:** `{e}`', None
        return reply, None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_db_assist_app(server, url_base_pathname):
    app = Dash(__name__, server=server, url_base_pathname=url_base_pathname,
               external_stylesheets=[dbc.themes.BOOTSTRAP, '/static/styles.css'])

    app.layout = db_assist_layout()
    register_db_assist_callbacks(app)

    return app

