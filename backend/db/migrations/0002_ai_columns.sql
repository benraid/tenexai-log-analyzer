-- 0002_ai_columns.sql
-- Caches for LLM-generated content. We store the briefing on the uploads row
-- and the per-anomaly explanation on the anomalies row so that re-renders
-- don't burn tokens. *_at columns let us show "generated 2 min ago" and let
-- a future implementation invalidate stale content.

ALTER TABLE uploads
  ADD COLUMN IF NOT EXISTS ai_briefing    TEXT,
  ADD COLUMN IF NOT EXISTS ai_briefing_at TIMESTAMPTZ;

ALTER TABLE anomalies
  ADD COLUMN IF NOT EXISTS ai_explanation    TEXT,
  ADD COLUMN IF NOT EXISTS ai_explanation_at TIMESTAMPTZ;
