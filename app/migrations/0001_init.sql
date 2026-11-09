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
    -- Schlüssel für device_sources.source (Devices\Pairing::storedSource); verlässt den Server nie.
    source_salt blob not null,
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

-- autoincrement: Die Nummer eines gelöschten (zusammengelegten) Geräts wird nie neu vergeben.
create table devices (
    id integer primary key autoincrement,
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

-- revoked_reason: warum der Schlüssel gesperrt ist ('repaired' = Gerät neu gekoppelt, 'revoked' = in der
-- Geräte-Ansicht gesperrt); leer, solange der Schlüssel gilt. Die Datenannahme nennt den Grund im 401.
-- sign_public_key: öffentlicher Ed25519-Schlüssel (32 Byte roh), den das Gerät beim Koppeln mit diesem Schlüssel
-- gemeldet hat; bleibt auch am gesperrten Eintrag. Leer, wenn er schon einem anderen Gerät gehörte (sign_keys_refused).
create table device_keys (
    key_hash blob primary key,
    device_id integer not null references devices(id),
    created_at integer not null default (cast(strftime('%s', 'now') as integer)),
    revoked_at integer,
    revoked_reason text check (revoked_reason in ('repaired', 'revoked')),
    sign_public_key blob check (sign_public_key is null or (typeof(sign_public_key) = 'blob' and length(sign_public_key) = 32))
);
create index device_keys_sign_idx on device_keys (sign_public_key);

-- Frühere Signaturschlüssel eines Geräts (sign_public_keys_previous beim Koppeln), 32 Byte roh. Zusammen mit
-- device_keys.sign_public_key sind das alle Signaturschlüssel des Geräts (Devices::signKeys). Ein Schlüssel gehört
-- genau einem Gerät; das prüft das Koppeln über beide Tabellen.
create table device_sign_keys (
    sign_public_key blob primary key check (typeof(sign_public_key) = 'blob' and length(sign_public_key) = 32),
    device_id integer not null references devices(id),
    created_at integer not null
);
create index device_sign_keys_device_idx on device_sign_keys (device_id);

-- Kennungen der Rechner (device_source des Plugins, 64 Hex-Zeichen) je Benutzer: Koppeln mit einer bekannten
-- Kennung trifft das Gerät, dem sie gehört. Ein Gerät kann mehrere Kennungen haben.
create table device_sources (
    user_id integer not null references users(id),
    source text not null check (length(source) = 64),
    device_id integer not null references devices(id),
    primary key (user_id, source)
);
create index device_sources_device_idx on device_sources (device_id);

create table pair_codes (
    id integer primary key,
    user_id integer not null references users(id),
    code_hash blob not null,
    expires_at integer not null,
    used_at integer,
    failed_attempts integer not null default 0,
    -- Leer: der Code legt ein neues Gerät an oder trifft das Gerät der Kennung; sonst koppelt er genau dieses Gerät neu.
    device_id integer references devices(id)
);

create table accounts (
    user_id integer not null references users(id),
    account_id text not null,
    email text,
    display_name text,
    first_seen_at integer not null default (cast(strftime('%s', 'now') as integer)),
    primary key (user_id, account_id)
);

-- Jede Sitzung liegt genau einmal auf dem Server, über alle Benutzer: wer sie zuerst liefert, besitzt sie.
create table sessions (
    user_id integer not null references users(id),
    session_id text not null,
    device_id integer,
    cc_version text,
    account_id text,
    flagged integer not null default 0,
    flag_reason text,
    primary key (session_id)
);
create index sessions_user_idx on sessions (user_id, session_id);

-- ts in Unix-Millisekunden (Plausibilität je Sekunde, Sortierung).
-- Jede Anfrage liegt genau einmal auf dem Server, über alle Benutzer: wer sie zuerst liefert, besitzt sie.
-- z und s: die signierte Inhaltszeile und ihre Signatur (Base64, 88 Zeichen) unverändert, wie geliefert; die übrigen
-- Spalten sind aus genau diesem z gelesen. Eine gespeicherte Zeile wird nie ersetzt (wiederholte Lieferung ändert nichts).
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
    z text not null,
    s text not null check (length(s) = 88),
    primary key (message_id, request_id)
);
create index requests_session_ts_idx on requests (user_id, session_id, ts);
-- Besitz einer Sitzung über alle Benutzer (Store: fremde Sitzungen).
create index requests_session_idx on requests (session_id);
create index requests_ts_idx on requests (user_id, ts);
create index requests_account_idx on requests (user_id, account_id);

create table request_tools (
    user_id integer not null references users(id),
    message_id text not null,
    request_id text not null,
    tool text not null,
    count integer not null,
    primary key (message_id, request_id, tool)
);

-- Signierte Vorgeschichte-Tage je Gerät: Inhaltszeile z und Signatur s unverändert, wie geliefert. Daraus gefüllt:
-- legacy_model_days (je Modell aus models) und legacy_activity_days (aus activity). Kommt ein Tag erneut, bleibt die
-- gespeicherte Zeile; beim Zusammenlegen zweier Geräte bleibt je Tag die Zeile mit der größeren Summe der Tokens als
-- Ganzes (Devices::merge), damit Werte und Signatur immer zu genau einer Zeile gehören.
create table legacy_day_lines (
    user_id integer not null references users(id),
    device_id integer not null,
    date text not null,
    z text not null,
    s text not null check (length(s) = 88),
    primary key (user_id, device_id, date)
);

create table legacy_model_days (
    user_id integer not null references users(id),
    device_id integer not null,
    date text not null,
    model text not null,
    tokens integer,
    -- 1: Tag laut Plugin fertig gerechnet (complete_before der Zeile); wird nie wieder 0.
    complete integer not null default 0,
    primary key (user_id, device_id, date, model)
);
-- Gleiche Tage anderer Geräte (Store: Abweisen gleicher Altbestandstage).
create index legacy_model_days_date_idx on legacy_model_days (date, model);

create table legacy_activity_days (
    user_id integer not null references users(id),
    device_id integer not null,
    date text not null,
    messages integer,
    sessions integer,
    tool_calls integer,
    complete integer not null default 0,
    primary key (user_id, device_id, date)
);
create index legacy_activity_days_date_idx on legacy_activity_days (date);

-- Was ein Gerät lieferte, aber schon woanders lag: Anfragen eines anderen Benutzers (oder in dessen Sitzung) und
-- abgewiesene Altbestandstage mit gleichen Werten wie bei einem anderen Gerät. Jede Anfrage und jeder Tag zählt je
-- Gerät einmal, auch wenn das Plugin sie erneut schickt; first_at (Unix-Sekunden) bleibt der erste Zeitpunkt.
-- Schlüssel: request mit message_id und request_id (date und model ''), legacy_model mit date und model,
-- legacy_activity mit date (model ''); nicht benutzte Teile sind ''.
-- Abgewiesene Tage tragen die eigenen gelieferten Werte und den eigenen Abschluss (wie legacy_model_days bzw.
-- legacy_activity_days: je Feld das Maximum, NULL ersetzt keinen Wert, complete einmal 1 bleibt 1); der Hinweis zum
-- Zusammenlegen vergleicht sie wie gespeicherte Tage. Bei request bleiben die Werte NULL.
create table elsewhere_hits (
    device_id integer not null,
    kind text not null check (kind in ('request', 'legacy_model', 'legacy_activity')),
    date text not null default '',
    model text not null default '',
    message_id text not null default '',
    request_id text not null default '',
    tokens integer,
    messages integer,
    sessions integer,
    tool_calls integer,
    complete integer not null default 0,
    first_at integer not null,
    primary key (device_id, kind, date, model, message_id, request_id)
);

create table settings (
    user_id integer primary key references users(id),
    flag_per_second integer not null default 50,
    flag_per_minute integer not null default 500
);

-- Ergänzungen für PHP (kein dauerhaft laufender Prozess, Einrichtung über die Webseite).

-- Schlüssel: public_url, trust_proxy ('0' | '1'), ca_pem, server_id.
create table server_settings (
    key text primary key,
    value text not null
);

-- server_id: Kennung dieses Servers (32 zufällige Byte als 64 Hex-Zeichen, klein) für GET /api/plugin/info; das Plugin
-- bildet daraus device_source. Sie entsteht beim Anlegen der Datenbank (Einrichtung) und ändert sich nie, auch nicht bei
-- einem Umzug mit derselben Datenbank. Die Trigger verhindern Ändern, Ersetzen und Löschen.
insert into server_settings (key, value) values ('server_id', lower(hex(randomblob(32))));
create trigger server_id_no_update before update on server_settings
when old.key = 'server_id' or new.key = 'server_id'
begin
    select raise(abort, 'server_id ist unveränderlich');
end;
create trigger server_id_no_delete before delete on server_settings
when old.key = 'server_id'
begin
    select raise(abort, 'server_id ist unveränderlich');
end;
create trigger server_id_no_insert before insert on server_settings
when new.key = 'server_id' and exists (select 1 from server_settings where key = 'server_id')
begin
    select raise(abort, 'server_id ist unveränderlich');
end;

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
