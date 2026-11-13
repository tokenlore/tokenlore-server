-- Vorgänger beim Koppeln (protocol/doc.md, „Koppeln“, „Vorgänger“). Ein Paar je Benutzer: Gerät device_id (B, der
-- gekoppelte Rechner) stammt nach predecessor_source von Gerät predecessor_id (A). Devices\Pairing::redeem legt den
-- Eintrag bei der Antwort `new` (state 'rejected': nie wieder fragen, auch nicht zum Zusammenlegen vorschlagen) oder
-- `later` (state 'open': die Webseite fragt) an. Die Antwort `same` legt kein B an und braucht keinen Eintrag.
-- Gespeichert wird nur das Paar der Geräte, nie predecessor_source. Ein gelöschtes Gerät nimmt seine Paare mit
-- (on delete cascade); Devices::merge hängt die Paare des abgegebenen Geräts vorher an das aufnehmende.
-- sign_key_match: Beim Koppeln von B gehörte einer der gesendeten Signaturschlüssel A (Angabe für die Frage auf der
-- Webseite; danach hat B den Schlüssel, A nicht mehr, und der Vergleich ließe sich nicht wiederholen).
create table device_predecessors (
    user_id integer not null references users(id),
    device_id integer not null references devices(id) on delete cascade,
    predecessor_id integer not null references devices(id) on delete cascade,
    state text not null check (state in ('open', 'rejected')),
    created_at integer not null,
    sign_key_match integer not null default 0 check (sign_key_match in (0, 1)),
    primary key (device_id, predecessor_id),
    check (device_id <> predecessor_id)
);
create index device_predecessors_predecessor_idx on device_predecessors (predecessor_id);
