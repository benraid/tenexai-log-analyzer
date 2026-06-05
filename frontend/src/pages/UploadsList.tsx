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
        <div className="border border-slate-700 rounded overflow-x-auto">
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
      )}
    </div>
  );
}
