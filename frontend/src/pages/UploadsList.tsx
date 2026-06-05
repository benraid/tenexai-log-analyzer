import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Upload } from "../lib/api";

export function UploadsListPage() {
  const nav = useNavigate();
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .listUploads()
      .then((u) => setUploads(u ?? []))
      .catch((e) => setErr(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Uploads</h1>
        <Link
          to="/uploads/new"
          className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-medium px-4 py-2 rounded"
        >
          + New upload
        </Link>
      </div>
      {err && <div className="text-red-400">{err}</div>}
      {loading ? (
        <div className="text-slate-400">Loading…</div>
      ) : uploads.length === 0 ? (
        <div className="text-slate-400">
          No uploads yet. Try{" "}
          <Link className="underline text-emerald-400" to="/uploads/new">
            uploading a log file
          </Link>
          .
        </div>
      ) : (
        <>
          {/* Mobile: stacked cards so nothing is hidden off-screen */}
          <ul className="md:hidden space-y-2">
            {uploads.map((u) => (
              <li
                key={u.id}
                onClick={() => nav(`/uploads/${u.id}`)}
                className="border border-slate-700 rounded p-3 bg-slate-900 active:bg-slate-800 cursor-pointer"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="font-mono text-sm break-all">{u.filename}</div>
                  <Link
                    to={`/uploads/${u.id}`}
                    onClick={(e) => e.stopPropagation()}
                    className="text-emerald-400 text-sm shrink-0"
                  >
                    View →
                  </Link>
                </div>
                <div className="mt-2 text-xs text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
                  <span>{u.parsed_rows} / {u.total_rows} rows</span>
                  <span>{new Date(u.uploaded_at).toLocaleString()}</span>
                </div>
              </li>
            ))}
          </ul>

          {/* Desktop: table */}
          <div className="hidden md:block border border-slate-700 rounded overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800 text-slate-300">
                <tr>
                  <th className="text-left px-4 py-2">Filename</th>
                  <th className="text-left px-4 py-2">Rows</th>
                  <th className="text-left px-4 py-2">Uploaded</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {uploads.map((u) => (
                  <tr
                    key={u.id}
                    onClick={() => nav(`/uploads/${u.id}`)}
                    className="border-t border-slate-700 cursor-pointer hover:bg-slate-800/60"
                  >
                    <td className="px-4 py-2 font-mono">{u.filename}</td>
                    <td className="px-4 py-2 whitespace-nowrap">
                      {u.parsed_rows} / {u.total_rows}
                    </td>
                    <td className="px-4 py-2 text-slate-400 whitespace-nowrap">
                      {new Date(u.uploaded_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-right whitespace-nowrap">
                      <Link
                        to={`/uploads/${u.id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-emerald-400 hover:underline"
                      >
                        View →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
