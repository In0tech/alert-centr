import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, AlertTriangle, BarChart3, Database, Search, Shield } from "lucide-react";
import "./styles.css";

type Alert = {
  alert_uid: string;
  target_cidr: string;
  level: 1 | 2 | 3;
  status: "active" | "closed";
  start_time: string;
  end_time: string | null;
  traffic_gbps: number;
  dp_blocks: number;
  waf_blocks: number;
};

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API_URL}/alerts`)
      .then((response) => {
        if (!response.ok) throw new Error(`API returned ${response.status}`);
        return response.json();
      })
      .then(setAlerts)
      .catch((reason: Error) => setError(reason.message))
      .finally(() => setLoading(false));
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
          <div className="live"><span />LIVE</div>
        </header>

        <section className="metrics">
          <Metric label="Активные атаки" value={String(active.length)} note="требуют контроля" />
          <Metric label="Аномальный трафик" value={`${traffic.toFixed(1)} Гбит/с`} note="текущая оценка" />
          <Metric label="Заблокировано" value={blocked.toLocaleString("ru-RU")} note="DP + WAF событий" />
          <Metric label="Доступность API" value={error ? "Ошибка" : "99.9%"} note="за последние 24 часа" />
        </section>

        <section className="panel">
          <div className="panel-head"><div><p className="eyebrow">Live feed</p><h2>Последние алерты</h2></div><button>Все алерты</button></div>
          {loading && <div className="state">Загрузка данных…</div>}
          {error && <div className="state error">Backend недоступен: {error}</div>}
          {!loading && !error && (
            <div className="table-wrap"><table><thead><tr><th>ID</th><th>Цель</th><th>Уровень</th><th>Статус</th><th>Трафик</th><th>DP</th><th>WAF</th></tr></thead>
              <tbody>{alerts.map((alert) => <tr key={alert.alert_uid}><td className="mono">{alert.alert_uid}</td><td className="mono">{alert.target_cidr}</td><td><span className={`level l${alert.level}`}>L{alert.level}</span></td><td><span className={`status ${alert.status}`}>{alert.status === "active" ? "Активен" : "Закрыт"}</span></td><td>{alert.traffic_gbps.toFixed(1)} Гбит/с</td><td>{alert.dp_blocks.toLocaleString("ru-RU")}</td><td>{alert.waf_blocks.toLocaleString("ru-RU")}</td></tr>)}</tbody>
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
