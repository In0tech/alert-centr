import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Database,
  Moon,
  RefreshCw,
  Search,
  Shield,
  Sun,
} from "lucide-react";
import "./styles.css";

type Alert = {
  alert_uid: string;
  target_cidr: string;
  level: number | null;
  status: "active" | "closed";
  start_time: string;
  end_time: string | null;
  max_bps: number;
  current_max_bps: number;
  traffic_gbps: number;
  dp_blocks: number;
  waf_blocks: number;
};

type Mitigation = {
  cidr: string;
  target_network_int: number;
  target_broadcast_int: number;
  mitigation: string | null;
  update_time_unix: number | null;
  update_time: string | null;
};

type MetricsSummary = {
  count?: number;
  avg_bps?: number;
  max_bps?: number;
  avg_duration_seconds?: number;
  [key: string]: unknown;
};

type Theme = "dark" | "light";
type Page = "overview" | "alerts" | "metrics" | "search" | "genie";

const DEFAULT_API_URL = `${window.location.protocol}//${window.location.hostname}:8000/api/v1`;
const API_URL = (import.meta.env.VITE_API_URL || DEFAULT_API_URL).replace(/\/$/, "");

const pageMeta: Record<Page, { eyebrow: string; title: string }> = {
  overview: { eyebrow: "Центр мониторинга", title: "Оперативная обстановка" },
  alerts: { eyebrow: "События защиты", title: "Алерты" },
  metrics: { eyebrow: "Аналитика", title: "Метрики атак" },
  search: { eyebrow: "Расследование", title: "Поиск событий" },
  genie: { eyebrow: "Данные защиты", title: "Genie DB" },
};

function pageFromHash(): Page {
  const value = window.location.hash.replace(/^#\/?/, "");
  return (["alerts", "metrics", "search", "genie"] as Page[]).includes(value as Page)
    ? (value as Page)
    : "overview";
}

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [mitigations, setMitigations] = useState<Mitigation[]>([]);
  const [metricsSummary, setMetricsSummary] = useState<MetricsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState<Page>(pageFromHash);
  const [searchText, setSearchText] = useState("");
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem("alert-centre-theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });

  useEffect(() => {
    const updatePage = () => setPage(pageFromHash());
    window.addEventListener("hashchange", updatePage);
    return () => window.removeEventListener("hashchange", updatePage);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("alert-centre-theme", theme);
  }, [theme]);

  const loadData = async () => {
    setLoading(true);
    try {
      const alertsResponse = await fetch(`${API_URL}/alerts`);
      if (!alertsResponse.ok) throw new Error(`API returned ${alertsResponse.status}`);
      const alertData: Alert[] = await alertsResponse.json();
      setAlerts(alertData);
      setError("");

      const [mitigationsResult, metricsResult] = await Promise.allSettled([
        fetch(`${API_URL}/mitigations`).then(async (r) => {
          if (!r.ok) throw new Error(String(r.status));
          return r.json() as Promise<Mitigation[]>;
        }),
        fetch(`${API_URL}/metrics/summary`).then(async (r) => {
          if (!r.ok) throw new Error(String(r.status));
          return r.json() as Promise<MetricsSummary>;
        }),
      ]);
      if (mitigationsResult.status === "fulfilled") setMitigations(mitigationsResult.value);
      if (metricsResult.status === "fulfilled") setMetricsSummary(metricsResult.value);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
    const timer = window.setInterval(() => void loadData(), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  const active = useMemo(() => alerts.filter((item) => item.status === "active"), [alerts]);
  const traffic = useMemo(() => active.reduce((sum, item) => sum + item.traffic_gbps, 0), [active]);
  const blocked = useMemo(() => alerts.reduce((sum, item) => sum + item.dp_blocks + item.waf_blocks, 0), [alerts]);
  const searchResults = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    if (!q) return alerts;
    return alerts.filter((item) =>
      [item.alert_uid, item.target_cidr, item.status, String(item.level ?? "")]
        .some((value) => value.toLowerCase().includes(q)),
    );
  }, [alerts, searchText]);

  const meta = pageMeta[page];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><Shield size={26} /><span>Alert Centre</span></div>
        <nav>
          <NavLink page="overview" current={page} icon={<Activity size={18} />} label="Обзор" />
          <NavLink page="alerts" current={page} icon={<AlertTriangle size={18} />} label="Алерты" />
          <NavLink page="metrics" current={page} icon={<BarChart3 size={18} />} label="Метрики" />
          <NavLink page="search" current={page} icon={<Search size={18} />} label="Поиск" />
          <NavLink page="genie" current={page} icon={<Database size={18} />} label="Genie DB" />
        </nav>
        <div className="sidebar-footer">Anti-DDoS Operations</div>
      </aside>

      <main>
        <header>
          <div><p className="eyebrow">{meta.eyebrow}</p><h1>{meta.title}</h1></div>
          <div className="header-actions">
            <button className="icon-button" onClick={() => void loadData()} title="Обновить данные"><RefreshCw size={17} /></button>
            <button
              className="theme-toggle"
              onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
              aria-label="Переключить тему"
              title={theme === "dark" ? "Светлая тема" : "Тёмная тема"}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
              <span>{theme === "dark" ? "Светлая" : "Тёмная"}</span>
            </button>
            <div className={`live ${error ? "offline" : ""}`}><span />{error ? "OFFLINE" : "LIVE"}</div>
          </div>
        </header>

        {page === "overview" && (
          <>
            <section className="metrics">
              <Metric label="Активные атаки" value={String(active.length)} note="требуют контроля" />
              <Metric label="Аномальный трафик" value={`${traffic.toFixed(1)} Гбит/с`} note="текущая оценка" />
              <Metric label="Заблокировано" value={blocked.toLocaleString("ru-RU")} note="DP + WAF событий" />
              <Metric label="Источник данных" value={error ? "Недоступен" : "Real-time"} note="SQLite + ClickHouse" />
            </section>
            <AlertPanel alerts={alerts.slice(0, 12)} loading={loading} error={error} title="Последние алерты" showAll />
          </>
        )}

        {page === "alerts" && (
          <section className="page-grid">
            <div className="summary-strip">
              <SmallStat label="Всего" value={alerts.length} />
              <SmallStat label="Активные" value={active.length} />
              <SmallStat label="L1" value={alerts.filter((a) => a.level === 1).length} />
              <SmallStat label="Закрытые" value={alerts.filter((a) => a.status === "closed").length} />
            </div>
            <AlertPanel alerts={alerts} loading={loading} error={error} title="Все алерты" />
          </section>
        )}

        {page === "metrics" && (
          <section className="page-grid">
            <div className="metrics metrics-page">
              <Metric label="Событий за период" value={String(metricsSummary?.count ?? alerts.length)} note="ClickHouse / Genie" />
              <Metric label="Средняя мощность" value={formatGbps(metricsSummary?.avg_bps)} note="среднее значение" />
              <Metric label="Пиковая мощность" value={formatGbps(metricsSummary?.max_bps)} note="максимум" />
              <Metric label="Средняя длительность" value={formatDuration(metricsSummary?.avg_duration_seconds)} note="по завершённым атакам" />
            </div>
            <section className="panel content-panel">
              <div className="panel-head"><div><p className="eyebrow">Traffic analytics</p><h2>Распределение по уровням</h2></div></div>
              <div className="level-bars">
                {[1, 2, 3].map((level) => {
                  const count = alerts.filter((a) => a.level === level).length;
                  const pct = alerts.length ? Math.round((count / alerts.length) * 100) : 0;
                  return <div className="level-row" key={level}><span>L{level}</span><div className="bar"><i style={{ width: `${pct}%` }} /></div><b>{count}</b><small>{pct}%</small></div>;
                })}
              </div>
            </section>
          </section>
        )}

        {page === "search" && (
          <section className="page-grid">
            <section className="panel search-panel">
              <div className="search-box"><Search size={19} /><input autoFocus value={searchText} onChange={(e) => setSearchText(e.target.value)} placeholder="UID, CIDR, статус или уровень..." /><span>{searchResults.length} результатов</span></div>
            </section>
            <AlertPanel alerts={searchResults} loading={loading} error={error} title="Результаты поиска" />
          </section>
        )}

        {page === "genie" && (
          <section className="page-grid">
            <div className="summary-strip">
              <SmallStat label="Записей защиты" value={mitigations.length} />
              <SmallStat label="Активных алертов" value={active.length} />
              <SmallStat label="Источник" value="SQLite / CH" />
              <SmallStat label="API" value={error ? "OFFLINE" : "ONLINE"} />
            </div>
            <section className="panel">
              <div className="panel-head"><div><p className="eyebrow">Mitigations</p><h2>Текущая защита объектов</h2></div></div>
              {error && <ErrorState error={error} />}
              {!error && mitigations.length === 0 && <div className="state">Данные mitigations пока отсутствуют.</div>}
              {!error && mitigations.length > 0 && <div className="table-wrap"><table><thead><tr><th>CIDR</th><th>Mitigation</th><th>Обновлено</th><th>Network int</th><th>Broadcast int</th></tr></thead><tbody>{mitigations.map((item) => <tr key={`${item.cidr}-${item.update_time_unix ?? 0}`}><td className="mono">{item.cidr}</td><td>{item.mitigation ?? "—"}</td><td>{formatDate(item.update_time)}</td><td className="mono">{item.target_network_int}</td><td className="mono">{item.target_broadcast_int}</td></tr>)}</tbody></table></div>}
            </section>
          </section>
        )}

        <div className="api-hint">API: <span className="mono">{API_URL}</span></div>
      </main>
    </div>
  );
}

function NavLink({ page, current, icon, label }: { page: Page; current: Page; icon: React.ReactNode; label: string }) {
  const href = page === "overview" ? "#/" : `#/${page}`;
  return <a href={href} className={current === page ? "active" : ""}>{icon}<span>{label}</span></a>;
}

function AlertPanel({ alerts, loading, error, title, showAll = false }: { alerts: Alert[]; loading: boolean; error: string; title: string; showAll?: boolean }) {
  return <section className="panel"><div className="panel-head"><div><p className="eyebrow">Live feed</p><h2>{title}</h2></div>{showAll && <a className="panel-action" href="#/alerts">Все алерты</a>}</div>
    {loading && <div className="state">Загрузка данных…</div>}
    {error && <ErrorState error={error} />}
    {!loading && !error && alerts.length === 0 && <div className="state">Алерты не найдены.</div>}
    {!loading && !error && alerts.length > 0 && <div className="table-wrap"><table><thead><tr><th>ID</th><th>Цель</th><th>Уровень</th><th>Статус</th><th>Трафик</th><th>DP</th><th>WAF</th></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.alert_uid}><td className="mono">{alert.alert_uid}</td><td className="mono">{alert.target_cidr}</td><td><span className={`level l${alert.level ?? 3}`}>L{alert.level ?? 3}</span></td><td><span className={`status ${alert.status}`}>{alert.status === "active" ? "Активен" : "Закрыт"}</span></td><td>{alert.traffic_gbps.toFixed(1)} Гбит/с</td><td>{alert.dp_blocks.toLocaleString("ru-RU")}</td><td>{alert.waf_blocks.toLocaleString("ru-RU")}</td></tr>)}</tbody></table></div>}
  </section>;
}

function ErrorState({ error }: { error: string }) {
  return <div className="state error"><strong>Backend недоступен: {error}</strong><span>Проверьте API, CORS и адрес сервера.</span></div>;
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return <article className="metric"><p>{label}</p><strong>{value}</strong><span>{note}</span></article>;
}

function SmallStat({ label, value }: { label: string; value: string | number }) {
  return <article className="small-stat"><span>{label}</span><strong>{value}</strong></article>;
}

function formatGbps(value: unknown): string {
  const number = typeof value === "number" ? value : 0;
  return `${(number / 1_000_000_000).toFixed(1)} Гбит/с`;
}

function formatDuration(value: unknown): string {
  const seconds = typeof value === "number" ? value : 0;
  if (!seconds) return "0 сек";
  if (seconds < 60) return `${Math.round(seconds)} сек`;
  return `${(seconds / 60).toFixed(1)} мин`;
}

function formatDate(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("ru-RU");
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
