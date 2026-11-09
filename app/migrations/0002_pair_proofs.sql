-- Angenommene Besitznachweise beim Koppeln (Fund Z9, Entscheidung Z9 a). Ein Nachweis signiert nur Vorsatz, server_id
-- und Code; vergibt der Server einen benutzten Code neu, wäre ein alter Nachweis wieder gültig. Deshalb merkt sich
-- Devices\Pairing::redeem jeden angenommenen Nachweis als Fingerabdruck (SHA-256 über Signaturschlüssel und Code, roh,
-- 32 Byte; die server_id ist je Server fest) und weist eine Wiederholung ab. Einträge werden nie gelöscht: Nach dem
-- Löschen gälte der Nachweis wieder. Höchstens ein Eintrag je erfolgreichem Koppeln.
create table pair_proofs (
    fingerprint blob primary key check (typeof(fingerprint) = 'blob' and length(fingerprint) = 32),
    used_at integer not null
);
