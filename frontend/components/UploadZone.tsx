"use client";

import { useRef, useState } from "react";
import { uploadFile, UploadResult } from "@/lib/api";

export default function UploadZone({ onUploaded }: { onUploaded: (r: UploadResult) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<UploadResult | null>(null);

  async function handleFiles(files: FileList | null) {
    if (!files?.length) return;
    setBusy(true);
    setError(null);
    try {
      for (const file of Array.from(files)) {
        const result = await uploadFile(file);
        setLastResult(result);
        onUploaded(result);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          handleFiles(e.dataTransfer.files);
        }}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
          dragging
            ? "border-cyan-400 bg-cyan-400/5"
            : "border-edge bg-panel hover:border-cyan-500/50"
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".csv,.tsv,.json,.ndjson,.jsonl,.log,.txt"
          multiple
          hidden
          onChange={(e) => handleFiles(e.target.files)}
        />
        <p className="text-lg font-medium text-slate-200">
          {busy ? "Parsing and scoring…" : "Drop raw log files here or click to browse"}
        </p>
        <p className="mt-1 text-sm text-slate-400">
          CSV, JSON, and NDJSON supported. Entries are parsed, normalized, and scored on upload.
        </p>
      </div>

      {error && (
        <p className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm text-red-300">
          {error}
        </p>
      )}
      {lastResult && !error && (
        <p className="mt-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-300">
          Ingested {lastResult.records_ingested} records from {lastResult.filename}
          {" — "}
          {Object.entries(lastResult.severity_breakdown)
            .map(([k, v]) => `${v} ${k}`)
            .join(", ")}
        </p>
      )}
    </div>
  );
}
