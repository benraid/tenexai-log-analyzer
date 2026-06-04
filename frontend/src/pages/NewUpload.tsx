import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";

export function NewUploadPage() {
  const nav = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  async function submit() {
    if (!file) return;
    setErr(null);
    setUploading(true);
    try {
      const res = await api.uploadFile(file);
      nav(`/uploads/${res.upload_id}`);
    } catch (e: any) {
      setErr(e.message || "upload failed");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <h1 className="text-2xl font-semibold">Upload a log file</h1>
      <p className="text-slate-400 text-sm">
        CSV with header row. Expected columns:{" "}
        <code className="text-slate-300">
          timestamp, username, src_ip, dst_ip, url, url_category, action, threat_name, threat_category, bytes_in, bytes_out, user_agent, referer
        </code>
        .
      </p>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const f = e.dataTransfer.files?.[0];
          if (f) setFile(f);
        }}
        className={`border-2 border-dashed rounded-lg p-10 text-center transition ${
          dragging ? "border-emerald-400 bg-emerald-500/5" : "border-slate-700"
        }`}
      >
        <div className="text-slate-400">
          Drop a .csv / .log here, or
          <label className="ml-2 text-emerald-400 underline cursor-pointer">
            browse
            <input
              type="file"
              className="hidden"
              accept=".csv,.log,.txt,text/csv,text/plain"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>
        </div>
        {file && (
          <div className="mt-3 text-sm text-slate-300">
            Selected: <span className="font-mono">{file.name}</span> ({Math.round(file.size / 1024)} KB)
          </div>
        )}
      </div>
      {err && <div className="text-red-400">{err}</div>}
      <button
        disabled={!file || uploading}
        onClick={submit}
        className="bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-medium px-4 py-2 rounded"
      >
        {uploading ? "Uploading…" : "Upload & analyze"}
      </button>
    </div>
  );
}
