import os
import io
import json
import time
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import requests
import streamlit as st

DB_PATH = "tiktok_posting.db"

AUTH_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
REVOKE_URL = "https://open.tiktokapis.com/v2/oauth/revoke/"
CREATOR_INFO_URL = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
VIDEO_INIT_URL = "https://open.tiktokapis.com/v2/post/publish/video/init/"
STATUS_URL = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

SCOPES = "user.info.basic,video.publish"
TIMEOUT = 60

st.set_page_config(page_title="TikTok Posting Manager", page_icon="🎬", layout="wide")


# -----------------------------
# Configuration
# -----------------------------
def secret_or_env(name, default=""):
    try:
        if name in st.secrets:
            return str(st.secrets[name]).strip()
    except Exception:
        pass
    return os.getenv(name, default).strip()


CLIENT_KEY = secret_or_env("TIKTOK_CLIENT_KEY")
CLIENT_SECRET = secret_or_env("TIKTOK_CLIENT_SECRET")
REDIRECT_URI = secret_or_env("TIKTOK_REDIRECT_URI")


# -----------------------------
# Database
# -----------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            open_id TEXT PRIMARY KEY,
            label TEXT,
            access_token TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            scope TEXT,
            access_expires_at TEXT,
            refresh_expires_at TEXT,
            connected_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            open_id TEXT NOT NULL,
            publish_id TEXT,
            filename TEXT,
            title TEXT,
            privacy_level TEXT,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            detail TEXT
        )
    """)
    conn.commit()
    return conn


def save_state(state):
    conn = db()
    conn.execute("INSERT OR REPLACE INTO oauth_states(state, created_at) VALUES (?,?)",
                 (state, now_iso()))
    conn.commit()
    conn.close()


def consume_state(state):
    conn = db()
    row = conn.execute("SELECT state FROM oauth_states WHERE state=?", (state,)).fetchone()
    if row:
        conn.execute("DELETE FROM oauth_states WHERE state=?", (state,))
        conn.commit()
    conn.close()
    return bool(row)


def save_account(token_data):
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(seconds=int(token_data.get("expires_in", 0)))
    refresh_exp = now + timedelta(seconds=int(token_data.get("refresh_expires_in", 0)))
    conn = db()
    conn.execute("""
        INSERT INTO accounts(
            open_id,label,access_token,refresh_token,scope,
            access_expires_at,refresh_expires_at,connected_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(open_id) DO UPDATE SET
            access_token=excluded.access_token,
            refresh_token=excluded.refresh_token,
            scope=excluded.scope,
            access_expires_at=excluded.access_expires_at,
            refresh_expires_at=excluded.refresh_expires_at,
            updated_at=excluded.updated_at
    """, (
        token_data["open_id"], token_data.get("open_id", "")[-8:],
        token_data["access_token"], token_data["refresh_token"],
        token_data.get("scope", ""),
        access_exp.isoformat(), refresh_exp.isoformat(),
        now.isoformat(), now.isoformat()
    ))
    conn.commit()
    conn.close()


def accounts():
    conn = db()
    rows = conn.execute("""
        SELECT open_id,label,scope,access_expires_at,refresh_expires_at,connected_at
        FROM accounts ORDER BY connected_at DESC
    """).fetchall()
    conn.close()
    return rows


def get_account(open_id):
    conn = db()
    row = conn.execute("""
        SELECT open_id,label,access_token,refresh_token,scope,
               access_expires_at,refresh_expires_at
        FROM accounts WHERE open_id=?
    """, (open_id,)).fetchone()
    conn.close()
    return row


def update_tokens(open_id, data):
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(seconds=int(data.get("expires_in", 0)))
    refresh_exp = now + timedelta(seconds=int(data.get("refresh_expires_in", 0)))
    conn = db()
    conn.execute("""
        UPDATE accounts SET access_token=?, refresh_token=?, scope=?,
            access_expires_at=?, refresh_expires_at=?, updated_at=?
        WHERE open_id=?
    """, (
        data["access_token"], data["refresh_token"], data.get("scope", ""),
        access_exp.isoformat(), refresh_exp.isoformat(), now.isoformat(), open_id
    ))
    conn.commit()
    conn.close()


def rename_account(open_id, label):
    conn = db()
    conn.execute("UPDATE accounts SET label=? WHERE open_id=?", (label.strip(), open_id))
    conn.commit()
    conn.close()


def remove_account(open_id):
    conn = db()
    conn.execute("DELETE FROM accounts WHERE open_id=?", (open_id,))
    conn.commit()
    conn.close()


def save_post(open_id, publish_id, filename, title, privacy, status, detail=""):
    conn = db()
    conn.execute("""
        INSERT INTO posts(open_id,publish_id,filename,title,privacy_level,created_at,status,detail)
        VALUES(?,?,?,?,?,?,?,?)
    """, (open_id, publish_id, filename, title, privacy, now_iso(), status, detail))
    conn.commit()
    conn.close()


def post_history():
    conn = db()
    rows = conn.execute("""
        SELECT id,open_id,publish_id,filename,title,privacy_level,created_at,status,detail
        FROM posts ORDER BY id DESC LIMIT 500
    """).fetchall()
    conn.close()
    return rows


def now_iso():
    return datetime.now(timezone.utc).isoformat()


db().close()


# -----------------------------
# OAuth
# -----------------------------
def oauth_url():
    state = secrets.token_urlsafe(32)
    save_state(state)
    params = {
        "client_key": CLIENT_KEY,
        "scope": SCOPES,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    return AUTH_URL + "?" + urlencode(params)


def exchange_code(code):
    r = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_key": CLIENT_KEY,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        },
        timeout=TIMEOUT,
    )
    data = r.json()
    if not r.ok or "access_token" not in data:
        raise RuntimeError(data.get("error_description") or data.get("error") or str(data))
    return data


def refresh_account(open_id):
    row = get_account(open_id)
    if not row:
        raise RuntimeError("Akun tidak ditemukan.")
    refresh_token = row[3]
    r = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_key": CLIENT_KEY,
            "client_secret": CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        timeout=TIMEOUT,
    )
    data = r.json()
    if not r.ok or "access_token" not in data:
        raise RuntimeError(data.get("error_description") or data.get("error") or str(data))
    update_tokens(open_id, data)
    return data["access_token"]


def valid_access_token(open_id):
    row = get_account(open_id)
    if not row:
        raise RuntimeError("Akun tidak ditemukan.")
    access_token = row[2]
    expires = datetime.fromisoformat(row[5])
    if expires <= datetime.now(timezone.utc) + timedelta(minutes=15):
        return refresh_account(open_id)
    return access_token


def revoke_account(open_id):
    row = get_account(open_id)
    if not row:
        return
    requests.post(
        REVOKE_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_key": CLIENT_KEY,
            "client_secret": CLIENT_SECRET,
            "token": row[2],
        },
        timeout=TIMEOUT,
    )
    remove_account(open_id)


# -----------------------------
# TikTok Content Posting API
# -----------------------------
def creator_info(token):
    r = requests.post(
        CREATOR_INFO_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=UTF-8",
        },
        json={},
        timeout=TIMEOUT,
    )
    data = r.json()
    if not r.ok or data.get("error", {}).get("code") not in (None, "", "ok"):
        err = data.get("error", {})
        raise RuntimeError(err.get("message") or err.get("code") or str(data))
    return data.get("data", {})


def init_video(token, file_size, title, privacy, disable_comment, disable_duet, disable_stitch):
    body = {
        "post_info": {
            "title": title,
            "privacy_level": privacy,
            "disable_comment": bool(disable_comment),
            "disable_duet": bool(disable_duet),
            "disable_stitch": bool(disable_stitch),
        },
        "source_info": {
            "source": "FILE_UPLOAD",
            "video_size": file_size,
            "chunk_size": file_size,
            "total_chunk_count": 1,
        },
    }
    r = requests.post(
        VIDEO_INIT_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=UTF-8",
        },
        json=body,
        timeout=TIMEOUT,
    )
    data = r.json()
    if not r.ok or data.get("error", {}).get("code") not in (None, "", "ok"):
        err = data.get("error", {})
        raise RuntimeError(err.get("message") or err.get("code") or str(data))
    return data["data"]


def upload_video(upload_url, video_bytes):
    size = len(video_bytes)
    r = requests.put(
        upload_url,
        headers={
            "Content-Type": "video/mp4",
            "Content-Length": str(size),
            "Content-Range": f"bytes 0-{size-1}/{size}",
        },
        data=video_bytes,
        timeout=300,
    )
    if not r.ok:
        raise RuntimeError(f"Upload gagal: HTTP {r.status_code} {r.text[:300]}")


def fetch_status(token, publish_id):
    r = requests.post(
        STATUS_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=UTF-8",
        },
        json={"publish_id": publish_id},
        timeout=TIMEOUT,
    )
    data = r.json()
    if not r.ok or data.get("error", {}).get("code") not in (None, "", "ok"):
        err = data.get("error", {})
        raise RuntimeError(err.get("message") or err.get("code") or str(data))
    return data.get("data", {})


# -----------------------------
# OAuth callback
# -----------------------------
query = st.query_params
if "code" in query:
    callback_state = query.get("state", "")
    callback_code = query.get("code", "")
    if not callback_state or not consume_state(callback_state):
        st.error("OAuth state tidak valid atau sudah digunakan.")
    elif not all([CLIENT_KEY, CLIENT_SECRET, REDIRECT_URI]):
        st.error("Konfigurasi TikTok Developer belum lengkap.")
    else:
        try:
            data = exchange_code(callback_code)
            save_account(data)
            st.success("Akun TikTok berhasil dihubungkan.")
            st.query_params.clear()
        except Exception as exc:
            st.error(f"Gagal menukar authorization code: {exc}")

if "error" in query:
    st.error(f"TikTok OAuth error: {query.get('error_description', query.get('error'))}")


# -----------------------------
# UI
# -----------------------------
st.title("🎬 TikTok Posting Manager")
st.caption("Content Posting API resmi TikTok • OAuth per akun • hingga 100 akun terotorisasi")

with st.sidebar:
    st.header("Developer App")
    st.write("Client Key:", "✅" if CLIENT_KEY else "❌")
    st.write("Client Secret:", "✅" if CLIENT_SECRET else "❌")
    st.write("Redirect URI:", REDIRECT_URI or "❌ belum diatur")
    st.caption("Simpan secret sebagai environment variables atau Streamlit secrets, bukan di source code.")

    if all([CLIENT_KEY, CLIENT_SECRET, REDIRECT_URI]):
        st.link_button("➕ Connect TikTok Account", oauth_url())
    else:
        st.warning("Isi TIKTOK_CLIENT_KEY, TIKTOK_CLIENT_SECRET, dan TIKTOK_REDIRECT_URI terlebih dahulu.")

tab_accounts, tab_post, tab_history = st.tabs(["Akun Terhubung", "Posting Video", "Riwayat"])

with tab_accounts:
    rows = accounts()
    st.metric("Akun terhubung", len(rows))
    if len(rows) >= 100:
        st.warning("Sudah mencapai 100 akun pada dashboard ini.")

    if not rows:
        st.info("Belum ada akun. Gunakan tombol Connect TikTok Account di sidebar.")
    else:
        for open_id, label, scope, access_exp, refresh_exp, connected_at in rows:
            with st.expander(f"{label or open_id[-8:]} • {open_id[-8:]}"):
                st.write("Scope:", scope)
                st.write("Access token expires:", access_exp)
                st.write("Refresh token expires:", refresh_exp)
                new_label = st.text_input("Label internal", value=label or "", key=f"label_{open_id}")
                c1, c2, c3 = st.columns(3)
                with c1:
                    if st.button("Simpan Label", key=f"save_{open_id}"):
                        rename_account(open_id, new_label)
                        st.rerun()
                with c2:
                    if st.button("Refresh Token", key=f"refresh_{open_id}"):
                        try:
                            refresh_account(open_id)
                            st.success("Token diperbarui.")
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))
                with c3:
                    if st.button("Disconnect", key=f"disconnect_{open_id}"):
                        try:
                            revoke_account(open_id)
                        finally:
                            st.rerun()

with tab_post:
    rows = accounts()
    if not rows:
        st.info("Hubungkan minimal satu akun terlebih dahulu.")
    else:
        labels = {f"{r[1] or r[0][-8:]} • {r[0][-8:]}": r[0] for r in rows}
        selected_label = st.selectbox("Akun tujuan", list(labels.keys()))
        open_id = labels[selected_label]

        try:
            token = valid_access_token(open_id)
            info = creator_info(token)
            username = info.get("creator_username", "")
            nickname = info.get("creator_nickname", "")
            st.success(f"Akun aktif: @{username} — {nickname}")

            privacy_options = info.get("privacy_level_options") or ["SELF_ONLY"]
            max_duration = info.get("max_video_post_duration_sec")
            if max_duration:
                st.caption(f"Durasi maksimum yang dilaporkan TikTok untuk akun ini: {max_duration} detik.")

            video = st.file_uploader("Pilih video MP4", type=["mp4"])
            title = st.text_area("Caption", max_chars=2200)
            privacy = st.selectbox("Privacy", privacy_options)

            c1, c2, c3 = st.columns(3)
            disable_comment = c1.checkbox("Nonaktifkan komentar", value=False)
            disable_duet = c2.checkbox("Nonaktifkan duet", value=False)
            disable_stitch = c3.checkbox("Nonaktifkan stitch", value=False)

            consent = st.checkbox(
                f"Saya menyetujui video ini dikirim ke akun @{username} dengan pengaturan di atas."
            )

            if st.button("🚀 Upload & Direct Post", type="primary", disabled=(video is None or not consent)):
                video_bytes = video.getvalue()
                with st.status("Mengirim video ke TikTok...", expanded=True) as status:
                    try:
                        st.write("1/3 Menginisialisasi posting...")
                        init = init_video(
                            token, len(video_bytes), title, privacy,
                            disable_comment, disable_duet, disable_stitch
                        )
                        publish_id = init["publish_id"]
                        upload_url = init["upload_url"]

                        st.write("2/3 Mengupload file video...")
                        upload_video(upload_url, video_bytes)

                        st.write("3/3 Upload selesai. Menyimpan publish_id...")
                        save_post(
                            open_id, publish_id, video.name, title, privacy,
                            "SUBMITTED", "Video berhasil dikirim ke TikTok."
                        )
                        status.update(label="Video berhasil dikirim.", state="complete")
                        st.success(f"Publish ID: {publish_id}")
                    except Exception as exc:
                        save_post(open_id, None, video.name, title, privacy, "ERROR", str(exc))
                        status.update(label="Posting gagal.", state="error")
                        st.error(str(exc))
        except Exception as exc:
            st.error(f"Tidak dapat memuat Creator Info: {exc}")

with tab_history:
    rows = post_history()
    if not rows:
        st.info("Belum ada riwayat posting.")
    else:
        for row in rows:
            pid, open_id, publish_id, filename, title, privacy, created_at, status_text, detail = row
            with st.expander(f"#{pid} • {filename} • {status_text}"):
                st.write("Publish ID:", publish_id or "-")
                st.write("Akun:", open_id[-8:])
                st.write("Privacy:", privacy)
                st.write("Waktu:", created_at)
                st.write("Caption:", title)
                st.write("Detail:", detail)
                if publish_id:
                    if st.button("Cek Status TikTok", key=f"status_{pid}"):
                        try:
                            token = valid_access_token(open_id)
                            result = fetch_status(token, publish_id)
                            st.json(result)
                        except Exception as exc:
                            st.error(str(exc))

st.divider()
st.caption(
    "Catatan: TikTok mewajibkan creator info terbaru dan persetujuan pengguna sebelum Direct Post. "
    "Aplikasi yang belum diaudit dibatasi ke posting private sesuai kebijakan TikTok."
)
