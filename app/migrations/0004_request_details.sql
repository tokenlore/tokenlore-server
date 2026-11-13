-- Merkmal request_details (protocol/doc.md, „Inhaltszeile: Anfrage“, „Inhaltszeile: Fehler“, „Server-Kennung“).
-- Neue Werte einer Anfrage, gelesen aus ihrer Zeile z; NULL, wenn die Zeile das Feld nicht hat (auch bei allen
-- Anfragen von vor dieser Umstellung).
alter table requests add column prompt_cache_requested text;
alter table requests add column tool_input_stream_ms integer;
alter table requests add column thinking_duration_ms integer;
alter table requests add column attribution_plugin text;
alter table requests add column attribution_agent text;
alter table requests add column cache_miss_reason text;

-- Fehlerzeilen (kind error): je API-Fehler die signierte Zeile z und ihre Signatur s unverändert, wie geliefert, und
-- die daraus gelesenen Werte (fehlende NULL; account_id NULL statt leer). Wie bei requests: eindeutig über alle
-- Benutzer, wer zuerst liefert, besitzt sie, eine gespeicherte Zeile wird nie ersetzt. ts in Unix-Millisekunden.
create table request_errors (
    user_id integer not null references users(id),
    message_id text not null,
    request_id text not null default '',
    session_id text not null,
    device_id integer not null,
    ts integer not null,
    utc_offset_min integer not null,
    subagent integer not null,
    account_id text,
    api_error_status integer,
    error text,
    rate_limit_type text,
    limit_status text,
    overage_status text,
    is_using_overage integer,
    resets_at integer,
    z text not null,
    s text not null check (length(s) = 88),
    primary key (message_id, request_id)
);
