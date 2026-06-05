import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, setToken } from "../lib/api";

export function LoginPage() {
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setLoading(true);
    try {
      const { token } = await api.login(username, password);
      setToken(token);
      nav("/uploads");
    } catch (e: any) {
      setErr(e.message || "login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm bg-slate-900 border border-slate-700 rounded-lg p-6 space-y-4"
      >
        <div>
          <div className="text-xl font-semibold">Tenex Log Analyzer</div>
          <div className="text-sm text-slate-400">Sign in to upload and analyze Zscaler logs.</div>
        </div>
        <div className="space-y-2">
          <label className="block text-sm text-slate-300">Username</label>
          <input
            className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
        </div>
        <div className="space-y-2">
          <label className="block text-sm text-slate-300">Password</label>
          <input
            className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {err && <div className="text-red-400 text-sm">{err}</div>}
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-medium py-2 rounded"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
        <div className="text-xs text-slate-500">Default seed: admin / admin123</div>
      </form>
    </div>
  );
}
