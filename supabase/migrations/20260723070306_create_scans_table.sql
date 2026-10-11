/*
# Create scans table for PhishGuard AI scan history

1. Purpose
   Persists every URL and email phishing scan performed in the app so history
   survives across sessions and devices. Previously history lived only in
   localStorage; this table moves it to the database.

2. New Tables
   - `scans`
     - `id` (uuid, primary key, defaults to gen_random_uuid())
     - `scan_type` (text, not null) — 'url' or 'email'
     - `label` (text, not null) — for URL scans: the raw URL; for email scans: the sender address
     - `sublabel` (text, not null default '') — for URL scans: normalized URL; for email scans: the subject line
     - `score` (int, not null) — 0-100 risk score
     - `verdict` (text, not null) — 'Safe', 'Suspicious', or 'Phishing'
     - `confidence` (int, not null) — 0-100 confidence percentage
     - `checks` (jsonb, not null default '[]') — array of heuristic check objects
     - `extracted_urls` (jsonb, nullable) — for email scans: array of analyzed URL result objects
     - `scanned_at` (timestamptz, not null, default now()) — when the scan was performed

3. Indexes
   - `scans_scanned_at_desc` on `scanned_at DESC` — history is ordered by recency
   - `scans_scan_type_idx` on `scan_type` — dashboard filters by scan type

4. Security
   - Enable RLS on `scans`.
   - This is a single-tenant app with NO sign-in screen, so all CRUD is open to
     `anon, authenticated` with `USING (true)` / `WITH CHECK (true)`. The data
     is intentionally shared/public across the demo app.

5. Notes
   - `checks` and `extracted_urls` are stored as jsonb to preserve the full
     heuristic breakdown and per-URL analysis without needing child tables.
   - `scanned_at` defaults to now() so inserts can omit it.
*/

CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_type text NOT NULL CHECK (scan_type IN ('url', 'email')),
  label text NOT NULL,
  sublabel text NOT NULL DEFAULT '',
  score int NOT NULL CHECK (score >= 0 AND score <= 100),
  verdict text NOT NULL CHECK (verdict IN ('Safe', 'Suspicious', 'Phishing')),
  confidence int NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  extracted_urls jsonb,
  scanned_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scans_scanned_at_desc ON scans (scanned_at DESC);
CREATE INDEX IF NOT EXISTS scans_scan_type_idx ON scans (scan_type);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_scans" ON scans;
CREATE POLICY "anon_select_scans" ON scans FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_scans" ON scans;
CREATE POLICY "anon_insert_scans" ON scans FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_scans" ON scans;
CREATE POLICY "anon_update_scans" ON scans FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_scans" ON scans;
CREATE POLICY "anon_delete_scans" ON scans FOR DELETE
  TO anon, authenticated USING (true);
