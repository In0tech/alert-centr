import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Database,
  Moon,
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

type Theme = "dark" | "light";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem("alert-centre-theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("alert-centre-theme", theme);
  }, [theme]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const response = await fetch(`${API_URL}/alerts`);
        if (!response.ok) throw new Error(`API returned ${response.status}`);
        const data: Alert[] = await response.json();
        if (!cancelled) {
          setAlerts(data);
          setError("");
        }
      } catch (reason) {
        if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    const timer = window.setInterval(load, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const active = useMemo(() => alerts.filter((item) => item.status === "active"), [alerts]);
  const traffic = useMemo(() => active.reduce((sum, item) => sum + item.traffic_gbps, 0), [active]);
  const blocked = useMemo(() => alerts.reduce((sum, item) => sum + item.dp_blocks + item.waf_blocks, 0), [alerts]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><Shield size={26} /><span>Alert Centre</span></div>
        <nav>
          <a className="active"><Activity size={18} />Обзор</a>
          <a><AlertTriangle size={18} />Алерты</a>
          <a><BarChart3 size={18} />Метрики</a>
          <a><Search size={18} />Поиск</a>
          <a><Database size={18} />Genie DB</a>
        </nav>
        <div className="sidebar-footer">Anti-DDoS Operations</div>
      </aside>

      <main>
        <header>
          <div><p className="eyebrow">Центр мониторинга</p><h1>Оперативная обстановка</h1></div>
          <div className="header-actions">
            <button
              className="theme-toggle"
              onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
              aria-label="Переключить тему"
              title={theme === "dark" ? "Светлая тема" : "Тёмная тема"}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
              <span>{theme === "dark" ? "Светлая" : "Тёмная"}</span>
            </button>
            <div className="live"><span />LIVE</div>
          </div>
        </header>

        <section className="metrics">
          <Metric label="Активные атаки" value={String(active.length)} note="требуют контроля" />
          <Metric label="Аномальный трафик" value={`${traffic.toFixed(1)} Гбит/с`} note="текущая оценка" />
          <Metric label="Заблокировано" value={blocked.toLocaleString("ru-RU")} note="DP + WAF событий" />
          <Metric label="Источник данных" value={error ? "Недоступен" : "Real-time"} note="SQLite + ClickHouse" />
        </section>

        <section className="panel">
          <div className="panel-head"><div><p className="eyebrow">Live feed</p><h2>Последние алерты</h2></div><button>Все алерты</button></div>
          {loading && <div className="state">Загрузка данных…</div>}
          {error && <div className="state error">Backend недоступен: {error}</div>}
          {!loading && !error && (
            <div className="table-wrap"><table><thead><tr><th>ID</th><th>Цель</th><th>Уровень</th><th>Статус</th><th>Трафик</th><th>DP</th><th>WAF</th></tr></thead>
              <tbody>{alerts.map((alert) => <tr key={alert.alert_uid}><td className="mono">{alert.alert_uid}</td><td className="mono">{alert.target_cidr}</td><td><span className={`level l${alert.level ?? 3}`}>L{alert.level ?? 3}</span></td><td><span className={`status ${alert.status}`}>{alert.status === "active" ? "Активен" : "Закрыт"}</span></td><td>{alert.traffic_gbps.toFixed(1)} Гбит/с</td><td>{alert.dp_blocks.toLocaleString("ru-RU")}</td><td>{alert.waf_blocks.toLocaleString("ru-RU")}</td></tr>)}</tbody>
            </table></div>
          )}
        </section>
      </main>
    </div>
  );
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return <article className="metric"><p>{label}</p><strong>{value}</strong><span>{note}</span></article>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
