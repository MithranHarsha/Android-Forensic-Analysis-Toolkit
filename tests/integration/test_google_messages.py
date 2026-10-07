from __future__ import annotations

import sqlite3
from pathlib import Path

from android_forensics.acquisition.ingest import ingest_source
from android_forensics.pipeline.runner import run_pipeline
from android_forensics.storage.case_store import CaseStore

BUGLE = "data/data/com.google.android.apps.messaging/databases"
TEL = "data/data/com.android.providers.telephony/databases"
SCHEMA = """
CREATE TABLE conversations(_id INTEGER PRIMARY KEY AUTOINCREMENT, sms_thread_id INT, name TEXT, participant_normalized_destination TEXT);
CREATE TABLE participants(_id INTEGER PRIMARY KEY AUTOINCREMENT, normalized_destination TEXT, sub_id INT);
CREATE TABLE messages(_id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id INT, sender_id INT, sent_timestamp INT, received_timestamp INT,
  message_protocol INT, message_status INT, seen INT, read INT, mms_subject TEXT);
CREATE TABLE parts(_id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INT, text TEXT, content_type TEXT, conversation_id INT);
"""


def build(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    c.execute("INSERT INTO conversations VALUES(1,10,'Ann','+12025550101')")
    c.execute("INSERT INTO participants VALUES(1,'+12025550101',-1)")
    ms = 1709280000000
    c.executemany("INSERT INTO messages(conversation_id,sender_id,sent_timestamp,received_timestamp,message_protocol,message_status,seen,read) VALUES(?,?,?,?,?,?,?,?)",
                  [(1, 1, ms - 1000, ms, 0, 100, 1, 1),        # incoming
                   (1, None, 0, ms + 60000, 0, 1, 1, 1),       # outgoing, complete
                   (1, 1, 0, ms + 120000, 5, 210, 1, 1),       # media / system: no text part
                   (1, 1, ms, ms + 180000, 0, 100, 1, 1)])     # incoming, two text parts
    c.executemany("INSERT INTO parts(message_id,text,content_type,conversation_id) VALUES(?,?,?,?)",
                  [(1, "hello from Ann", "text/plain", 1), (2, "on my way", "text/plain", 1), (3, None, "image/jpeg", 1),
                   (4, "part one", "text/plain", 1), (4, "part two", "text/plain", 1)])
    c.commit()
    c.close()


def analyse(tmp_path: Path, ev: Path) -> CaseStore:
    s = CaseStore.create(tmp_path / "case", "c", "t")
    ingest_source(s, ev)
    run_pipeline(s)
    return s


def test_messages_are_joined_into_ordinary_sms_artifacts(tmp_path):
    build(tmp_path / "ev" / BUGLE / "bugle_db")
    s = analyse(tmp_path, tmp_path / "ev")
    rows = [dict(r) for r in s.q("SELECT status, summary, flags_json, fields_json, parser FROM artifacts WHERE artifact_type='sms' ORDER BY id")]
    assert len(rows) == 4 and {r["parser"] for r in rows} == {"google_messages"} and {r["status"] for r in rows} == {"ACTIVE"}
    import json
    f = [json.loads(r["fields_json"]) for r in rows]
    assert [x["direction"] for x in f] == ["RECEIVED", "SENT", "RECEIVED", "RECEIVED"]
    assert [x["address"] for x in f] == ["+12025550101"] * 4                      # the conversation's counterpart, for both directions
    assert f[0]["body"] == "hello from Ann" and f[3]["body"] == "part one\npart two"
    assert f[2]["body"] is None and "no_text_part:image/jpeg" in rows[2]["flags_json"]   # reported, not dropped
    assert "Google Messages SENT to +12025550101" in rows[1]["summary"]


def test_aosp_sms_table_is_not_claimed_by_the_google_parser(tmp_path):
    p = tmp_path / "ev" / TEL / "mmssms.db"
    p.parent.mkdir(parents=True)
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER, body TEXT)")
    c.execute("INSERT INTO sms VALUES(1,'+12025550123',1709280000000,1,'hi')")
    c.commit()
    c.close()
    s = analyse(tmp_path, tmp_path / "ev")
    assert [r["parser"] for r in s.q("SELECT parser FROM artifacts WHERE artifact_type='sms'")] == ["sms"]
