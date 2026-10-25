-- Anfangsschema der SQLite-Datenbank (entspricht Go-Migrationen 0001-0004 plus Ergänzungen für PHP).
--
-- Abbildung der PostgreSQL-Typen:
--   Zeitpunkte (timestamptz)   -> INTEGER, Unix-Sekunden; nur requests.ts in Unix-MILLISEKUNDEN
--   date                       -> TEXT 'JJJJ-MM-TT'
--   bytea -> BLOB, bigserial -> INTEGER PRIMARY KEY, jsonb -> TEXT (JSON), boolean -> INTEGER 0/1
-- Prüfungen mit regulären Ausdrücken (z. B. users.username) macht der PHP-Code, nicht die Datenbank.
-- Die Go-Umstellung 0004 (alle Web-Sitzungen löschen) entfällt: die Tabelle ist hier neu und leer.

create table users (
    id integer primary key,
    username text unique not null,
    pw_hash text not null,
    project_salt blob not null,
    failed_logins integer not null default 0,
    locked_until integer,
    created_at integer not null default (cast(strftime('%s', 'now') as integer)),
    role text not null default 'member' check (role in ('admin', 'member')),
    disabled_at integer
);

create table web_sessions (
    token_hash blob primary key,
    user_id integer not null references users(id),
    csrf_token text not null,
    created_at integer not null default (cast(strftime('%s', 'now') as integer)),
    expires_at integer not null
);

create table devices (
    id integer primary key,
    user_id integer not null references users(id),
    name text not null check (length(name) between 1 and 64),
    os text,
    arch text,
    tz text,
    plugin_version text,
    created_at integer not null default (cast(strftime('%s', 'now') as integer)),
    last_seen_at integer,
    revoked_at integer
);

create table device_keys (
    key_hash blob primary key,
    device_id integer not null references devices(id),
    created_at integer not null default (cast(strftime('%s', 'now') as integer)),
    revoked_at integer
);

create table pair_codes (
    id integer primary key,
    user_id integer not null references users(id),
    code_hash blob not null,
    expires_at integer not null,
    used_at integer,
    failed_attempts integer not null default 0
);

create table accounts (
    user_id integer not null references users(id),
    account_id text not null,
    email text,
    display_name text,
    first_seen_at integer not null default (cast(strftime('%s', 'now') as integer)),
    primary key (user_id, account_id)
);

create table sessions (
    user_id integer not null references users(id),
    session_id text not null,
    device_id integer,
    project_id text,
    cc_version text,
    account_id text,
    flagged integer not null default 0,
    flag_reason text,
    primary key (user_id, session_id)
);

-- Manuelle Zuordnung "Konto unbekannt": jede Zuordnung ist ein Datensatz und lässt sich rückgängig machen.
create table account_assignments (
    id integer primary key,
    user_id integer not null references users(id),
    device_id integer not null,
    local_from text not null,
    local_to text not null,
    account_id text not null,
    created_at integer not null default (cast(strftime('%s', 'now') as integer)),
    undone_at integer,
    check (local_from <= local_to)
);
create index account_assignments_user_idx on account_assignments (user_id, id);

-- ts in Unix-Millisekunden (Plausibilität je Sekunde, Sortierung).
create table requests (
    user_id integer not null references users(id),
    message_id text not null,
    request_id text not null default '',
    session_id text not null,
    device_id integer not null,
    ts integer not null,
    utc_offset_min integer not null,
    model text not null,
    input integer,
    output integer,
    cache_create integer,
    cache_read integer,
    cache_1h integer,
    cache_5m integer,
    thinking integer,
    web_search integer,
    web_fetch integer,
    stop_reason text,
    subagent integer,
    account_id text,
    extra text,
    assignment_id integer,
    primary key (user_id, message_id, request_id)
);
create index requests_session_ts_idx on requests (user_id, session_id, ts);
create index requests_ts_idx on requests (user_id, ts);
create index requests_assignment_idx on requests (user_id, assignment_id);
create index requests_account_idx on requests (user_id, account_id);

create table request_tools (
    user_id integer not null references users(id),
    message_id text not null,
    request_id text not null,
    tool text not null,
    count integer not null,
    primary key (user_id, message_id, request_id, tool)
);

create table legacy_model_days (
    user_id integer not null references users(id),
    device_id integer not null,
    date text not null,
    model text not null,
    tokens integer,
    primary key (user_id, device_id, date, model)
);

create table legacy_activity_days (
    user_id integer not null references users(id),
    device_id integer not null,
    date text not null,
    messages integer,
    sessions integer,
    tool_calls integer,
    primary key (user_id, device_id, date)
);

create table settings (
    user_id integer primary key references users(id),
    flag_per_second integer not null default 50,
    flag_per_minute integer not null default 500
);

-- Ergänzungen für PHP (kein dauerhaft laufender Prozess, Einrichtung über die Webseite).

-- Schlüssel: public_url, trust_proxy ('0' | '1'), ca_pem.
create table server_settings (
    key text primary key,
    value text not null
);

-- Rate-Limits (früher im Speicher des Go-Servers): Token-Bucket je Schlüssel.
create table rate_limits (
    bucket text primary key,
    tokens real not null,
    updated_ms integer not null,
    -- Rate (Tokens je ms) und Burst der letzten Anfrage: daran erkennt das Aufräumen volle Buckets.
    per_ms real not null,
    burst integer not null
);
-- Aufräumen (Leerlauf und Obergrenze) sucht die ältesten Einträge.
create index rate_limits_updated_idx on rate_limits (updated_ms);

-- Sperre pro Gerät, damit dasselbe Gerät nicht zwei Lieferungen gleichzeitig schreibt.
create table device_locks (
    device_id integer primary key,
    until_ms integer not null
);

-- Einmalcodes zum Zurücksetzen des Administrator-Zugangs.
create table recovery_codes (
    code_hash blob primary key,
    expires_at integer not null
);

-- Stand der Umstellungen; Migrator führt die Zeile nach (genau eine).
create table schema_version (
    version integer not null
);

-- Tageswerte je Nutzer, Gerät, lokalem Tag und Modell.
--
-- Altbestand (legacy_model_days, aus stats-cache.json) wird bewusst NIE mit
-- Einzelanfragen summiert. Messung vom 24.10.2026: stats-cache zählt jede
-- Zeile ohne Entdoppelung; auf 8 von 8 Tagen entsprach der Wert exakt der
-- Summe aller Zeilen über alle vier Token-Felder, also 2- bis 3-mal zu viel.
-- Zählweise und Modellnamen sind mit den Einzelanfragen nicht vergleichbar.
-- Deshalb erscheinen Altbestandszeilen nur für (Nutzer, Gerät, Tag) ohne
-- jede Anfrage (egal bei welchem Modell) und tragen source = 'legacy'.
-- Die Oberfläche darf Altbestandswerte nur gekennzeichnet anzeigen.
-- Lokaler Tag einer Anfrage: Sekunden seit 1970 plus Zeitzonenversatz des Geräts.
create view daily_model_usage as
select r.user_id,
       r.device_id,
       date(r.ts / 1000 + r.utc_offset_min * 60, 'unixepoch') as local_date,
       r.model,
       count(*) as requests,
       sum(r.input) as input,
       sum(r.output) as output,
       sum(r.cache_create) as cache_create,
       sum(r.cache_read) as cache_read,
       'requests' as source
from requests r
group by r.user_id, r.device_id,
         date(r.ts / 1000 + r.utc_offset_min * 60, 'unixepoch'),
         r.model
union all
select l.user_id,
       l.device_id,
       l.date as local_date,
       l.model,
       null as requests,
       null as input,
       null as output,
       null as cache_create,
       l.tokens as cache_read,
       'legacy' as source
from legacy_model_days l
where not exists (
    select 1 from requests r
    where r.user_id = l.user_id
      and r.device_id = l.device_id
      and date(r.ts / 1000 + r.utc_offset_min * 60, 'unixepoch') = l.date
);
