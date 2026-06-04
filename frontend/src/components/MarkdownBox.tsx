import ReactMarkdown from "react-markdown";

// Thin wrapper around react-markdown so every AI-rendered surface has the same
// typography and spacing. Tailwind's `prose` plugin would also work; this is
// scoped to keep the dep tail small.
export function MarkdownBox({ children }: { children: string }) {
  return (
    <div className="text-sm text-slate-200 leading-relaxed space-y-2 [&_strong]:text-white [&_h3]:text-base [&_h3]:font-semibold [&_h3]:text-slate-100 [&_h3]:mt-2 [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1 [&_p]:text-slate-300 [&_code]:bg-slate-800 [&_code]:px-1 [&_code]:rounded">
      <ReactMarkdown>{children}</ReactMarkdown>
    </div>
  );
}
