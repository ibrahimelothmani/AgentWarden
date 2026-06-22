import { useState, useEffect, useCallback } from "react";

/* ── constants ─────────────────────────────────────────────────── */
const API_BASE = import.meta.env.VITE_API_BASE ?? "";
const POLL_MS  = 5_000;

/* ── tiny helpers ───────────────────────────────────────────────── */
function fmtDate(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function severityColor(s) {
  return { critical: "bg-red-500/20 text-red-300 ring-red-500/30",
           high:     "bg-orange-500/20 text-orange-300 ring-orange-500/30",
           medium:   "bg-yellow-500/20 text-yellow-300 ring-yellow-500/30",
           low:      "bg-blue-500/20 text-blue-300 ring-blue-500/30",
  }[s] ?? "bg-gray-500/20 text-gray-300 ring-gray-500/30";
}

/* ── sub-components ─────────────────────────────────────────────── */
function VerdictBadge({ verdict }) {
  const approved = verdict === "APPROVED";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset
      ${approved
        ? "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20"
        : "bg-red-500/10 text-red-400 ring-red-500/20"}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${approved ? "bg-emerald-400" : "bg-red-400"}`} />
      {verdict}
    </span>
  );
}

function ViolationList({ violations }) {
  if (!violations?.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {violations.map((v, i) => (
        <span key={i}
          className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-mono ring-1 ring-inset ${severityColor(v.severity)}`}
          title={v.message}>
          {v.rule}
        </span>
      ))}
    </div>
  );
}

function IncidentRow({ inc }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <li className="group">
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full text-left px-4 py-3.5 hover:bg-white/[0.03] transition-colors rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <VerdictBadge verdict={inc.verdict} />
              <span className="font-mono text-sm text-gray-200 truncate">{inc.target_repo}</span>
              <span className="text-xs text-gray-500">by {inc.agent_id}</span>
            </div>
            <p className="mt-1 font-mono text-xs text-gray-500 truncate max-w-xl">
              {inc.payload}
            </p>
            <ViolationList violations={inc.violations} />
          </div>
          <div className="shrink-0 text-right">
            <p className="text-xs text-gray-500">{fmtDate(inc.created_at)}</p>
            <p className="mt-1 text-xs text-gray-600 font-mono">{inc.id}</p>
          </div>
        </div>

        {expanded && inc.violations?.length > 0 && (
          <div className="mt-3 space-y-1.5 border-t border-white/5 pt-3">
            {inc.violations.map((v, i) => (
              <div key={i} className="text-xs text-gray-400 flex gap-2">
                <span className={`shrink-0 rounded-md px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset ${severityColor(v.severity)}`}>
                  {v.phase}
                </span>
                <span>{v.message}</span>
              </div>
            ))}
          </div>
        )}
      </button>
    </li>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="rounded-xl bg-white/[0.04] ring-1 ring-white/10 px-5 py-4">
      <p className="text-sm text-gray-400">{label}</p>
      <p className={`mt-1 text-3xl font-bold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

/* ── main app ───────────────────────────────────────────────────── */
export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [lastFetch, setLastFetch] = useState(null);

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/incidents`);
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const data = await res.json();
      setIncidents(data ?? []);
      setError(null);
      setLastFetch(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    const id = setInterval(fetchIncidents, POLL_MS);
    return () => clearInterval(id);
  }, [fetchIncidents]);

  const total    = incidents.length;
  const approved = incidents.filter(i => i.verdict === "APPROVED").length;
  const rejected = total - approved;
  const criticals = incidents.flatMap(i => i.violations ?? []).filter(v => v.severity === "critical").length;

  return (
    <div className="min-h-screen bg-gray-950 font-sans antialiased">
      {/* ── header ── */}
      <header className="border-b border-white/5 bg-gray-950/80 backdrop-blur sticky top-0 z-10">
        <div className="mx-auto max-w-6xl flex items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="text-2xl select-none">🛡️</span>
            <div>
              <h1 className="text-base font-semibold text-white">AgentWarden</h1>
              <p className="text-xs text-gray-500">GitOps Admission Controller</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {lastFetch && (
              <p className="text-xs text-gray-600 hidden sm:block">
                updated {lastFetch.toLocaleTimeString()}
              </p>
            )}
            <button
              onClick={fetchIncidents}
              className="rounded-md px-3 py-1.5 text-xs font-medium bg-white/5 hover:bg-white/10 text-gray-300 ring-1 ring-white/10 transition-colors">
              Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8 space-y-8">
        {/* ── stats ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="Total intercepts" value={total}     color="text-white" />
          <StatCard label="Approved"          value={approved} color="text-emerald-400" />
          <StatCard label="Rejected"          value={rejected} color="text-red-400" />
          <StatCard label="Critical findings" value={criticals} color="text-orange-400" />
        </div>

        {/* ── incident list ── */}
        <section>
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Incident History
          </h2>

          {loading && (
            <div className="flex items-center justify-center py-16 text-gray-500 text-sm gap-2">
              <span className="animate-spin">⟳</span> Loading incidents…
            </div>
          )}

          {error && (
            <div className="rounded-lg bg-red-500/10 ring-1 ring-red-500/20 px-4 py-3 text-sm text-red-400">
              <strong>API error:</strong> {error} — is AgentWarden running on {API_BASE || "localhost:8080"}?
            </div>
          )}

          {!loading && !error && incidents.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-gray-600 text-sm gap-2">
              <span className="text-4xl">✅</span>
              No incidents yet. POST something to /v1/intercept to get started.
            </div>
          )}

          {!loading && !error && incidents.length > 0 && (
            <ul className="divide-y divide-white/5 rounded-xl bg-white/[0.02] ring-1 ring-white/8">
              {incidents.map(inc => (
                <IncidentRow key={inc.id} inc={inc} />
              ))}
            </ul>
          )}
        </section>
      </main>
    </div>
  );
}
