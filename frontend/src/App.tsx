import { BrowserRouter, Routes, Route, Navigate, useLocation, useNavigate, Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { clearToken, getToken, api } from "./lib/api";
import { LoginPage } from "./pages/Login";
import { UploadsListPage } from "./pages/UploadsList";
import { NewUploadPage } from "./pages/NewUpload";
import { UploadDetailPage } from "./pages/UploadDetail";

function Protected({ children }: { children: React.ReactNode }) {
  const loc = useLocation();
  const [state, setState] = useState<"loading" | "ok" | "bad">("loading");
  useEffect(() => {
    if (!getToken()) {
      setState("bad");
      return;
    }
    api
      .me()
      .then(() => setState("ok"))
      .catch(() => setState("bad"));
  }, []);
  if (state === "loading") return <div className="p-6 text-slate-400">Loading…</div>;
  if (state === "bad") return <Navigate to="/login" state={{ from: loc }} replace />;
  return <>{children}</>;
}

function TopBar() {
  const nav = useNavigate();
  return (
    <header className="border-b border-slate-700 bg-slate-900 px-6 py-3 flex items-center justify-between">
      <Link to="/uploads" className="flex items-center gap-3 hover:opacity-80">
        <div className="w-2 h-2 rounded-full bg-emerald-400" />
        <span className="font-semibold tracking-wide">Tenex Log Analyzer</span>
      </Link>
      <button
        className="text-sm text-slate-400 hover:text-white"
        onClick={() => {
          clearToken();
          nav("/login");
        }}
      >
        Log out
      </button>
    </header>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <TopBar />
      <main className="p-6 max-w-7xl mx-auto">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/uploads"
          element={
            <Protected>
              <Shell>
                <UploadsListPage />
              </Shell>
            </Protected>
          }
        />
        <Route
          path="/uploads/new"
          element={
            <Protected>
              <Shell>
                <NewUploadPage />
              </Shell>
            </Protected>
          }
        />
        <Route
          path="/uploads/:id"
          element={
            <Protected>
              <Shell>
                <UploadDetailPage />
              </Shell>
            </Protected>
          }
        />
        <Route path="*" element={<Navigate to="/uploads" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
