-- ============================================================
--  IronLedger — Supabase Schema
--  Run this entire script once in the Supabase SQL Editor:
--  https://app.supabase.com → Your Project → SQL Editor → New Query
-- ============================================================

-- ── 1. ICS Events (off-chain mutable database) ──────────────
-- This is the "tamper-able" record store that IronLedger's
-- blockchain tamper-detection engine audits.

CREATE TABLE IF NOT EXISTS public.ics_events (
    event_id             BIGINT PRIMARY KEY,
    timestamp            DOUBLE PRECISION NOT NULL,
    source               TEXT NOT NULL,
    command_type         TEXT NOT NULL,
    entity_id            TEXT NOT NULL,
    parameters           TEXT DEFAULT '{}',        -- JSON string
    plant_state_snapshot TEXT DEFAULT '{}',        -- JSON string
    created_at           TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE public.ics_events IS
    'Off-chain ICS command event log — the mutable database that can be tampered with. '
    'Blockchain hashes in blockchain_blocks prove any alteration here.';

-- ── 2. Blockchain Blocks (immutable ledger mirror) ──────────
-- Mirror of the in-memory BlockchainLedger.chain.
-- In a production deployment this would be read directly from
-- the Ethereum Sepolia node / smart contract.

CREATE TABLE IF NOT EXISTS public.blockchain_blocks (
    block_index   BIGINT PRIMARY KEY,
    event_id      BIGINT REFERENCES public.ics_events(event_id) ON DELETE SET NULL,
    event_hash    TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    timestamp     BIGINT NOT NULL,
    source        TEXT NOT NULL,
    command_type  TEXT NOT NULL,
    entity_id     TEXT NOT NULL,
    tx_hash       TEXT,
    block_number  BIGINT,
    recorded_by   TEXT,
    status        TEXT DEFAULT 'CONFIRMED_ON_CHAIN',
    etherscan_url TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE public.blockchain_blocks IS
    'Mirror of the immutable blockchain anchor ledger. '
    'event_hash is the SHA-256 digest anchored on Ethereum Sepolia.';

-- ── 3. Forensic Cases (saved investigation records) ─────────
-- Each time a forensic reconstruction is run and saved, a row
-- is inserted here as a permanent investigation case file.

CREATE TABLE IF NOT EXISTS public.forensic_cases (
    id                   BIGSERIAL PRIMARY KEY,
    case_name            TEXT NOT NULL,
    attack_scenario      TEXT,
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    events_analyzed      INT DEFAULT 0,
    tamper_detected      BOOLEAN DEFAULT FALSE,
    tampered_records     INT DEFAULT 0,
    root_cause_source    TEXT,
    root_cause_command   TEXT,
    root_cause_entity    TEXT,
    forensic_conclusion  TEXT,
    attribution_actor    TEXT,
    confidence_score     REAL DEFAULT 0,
    mitre_techniques     TEXT DEFAULT '[]',    -- JSON array string
    timeline             TEXT DEFAULT '[]',    -- JSON array string
    threat_intel         TEXT DEFAULT '{}',    -- JSON object string
    telemetry_snapshot   TEXT DEFAULT '{}'     -- JSON object string
);

COMMENT ON TABLE public.forensic_cases IS
    'Saved forensic reconstruction cases. Each row is a complete investigation record '
    'including timeline, attribution, MITRE techniques, and blockchain audit results.';

-- ── Row-Level Security (optional but recommended) ────────────
-- Uncomment the block below if you want the anon key to have
-- read-only access and require a service-role key to write.
-- For demo / hackathon use, keeping RLS disabled is fine.

-- ALTER TABLE public.ics_events     ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public.blockchain_blocks ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE public.forensic_cases ENABLE ROW LEVEL SECURITY;

-- CREATE POLICY "anon_read_ics"       ON public.ics_events        FOR SELECT USING (TRUE);
-- CREATE POLICY "anon_read_blocks"    ON public.blockchain_blocks FOR SELECT USING (TRUE);
-- CREATE POLICY "anon_read_cases"     ON public.forensic_cases    FOR SELECT USING (TRUE);

-- ── Helpful Indexes ──────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_ics_events_timestamp        ON public.ics_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_blockchain_blocks_event_id  ON public.blockchain_blocks(event_id);
CREATE INDEX IF NOT EXISTS idx_forensic_cases_created_at   ON public.forensic_cases(created_at DESC);
