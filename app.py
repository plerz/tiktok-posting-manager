import os
import secrets
import sqlite3
import mimetypes
from datetime import datetime
from urllib.parse import urlencode

import requests
from flask import (
    Flask, render_template, redirect, request, session,
    url_for, flash, send_from_directory
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

DB = os.environ.get("DATABASE_PATH", "kelolatiktok.db")
CLIENT_KEY = os.environ.get("TIKTOK_CLIENT_KEY", "")
CLIENT_SECRET = os.environ.get("TIKTOK_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get(
    "TIKTOK_REDIRECT_URI",
    "https://tiktok.islammoderat.my.id/auth/tiktok/callback"
)
SCOPES = os.environ.get(
    "TIKTOK_SCOPES",
    "user.info.basic,video.publish"
)

AUTH_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
USER_URL = "https://open.tiktokapis.com/v2/user/info/"
CREATOR_URL = "https://open.tiktokapis.com/v2/post/publish/creator_info/query/"
DIRECT_POST_INIT_URL = "https://open.tiktokapis.com/v2/post/publish/video/init/"
POST_STATUS_URL = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

VERIFY_FILENAME = "tiktok8X1qCm95yvCX8YUCrVKwJVg1gjLQxAqB.txt"

# Keep this conservative for the web app. TikTok's API may support larger
# files, but large uploads can exceed hosting request/runtime limits.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 100 * 1024 * 1024))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS accounts(
            open_id TEXT PRIMARY KEY,
            display_name TEXT,
            avatar_url TEXT,
            access_token TEXT,
            refresh_token TEXT,
            scope TEXT,
            expires_in INTEGER,
            connected_at TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS publish_jobs(
            publish_id TEXT PRIMARY KEY,
            open_id TEXT NOT NULL,
            caption TEXT,
            privacy_level TEXT,
            status TEXT,
            created_at TEXT,
            last_response TEXT
        )"""
    )
    conn.commit()
    conn.close()


@app.before_request
def _init():
    init_db()


def get_account(open_id):
    conn = db()
    row = conn.execute(
        "SELECT * FROM accounts WHERE open_id=?", (open_id,)
    ).fetchone()
    conn.close()
    return row


def tiktok_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=UTF-8",
    }


def creator_info(account):
    try:
        response = requests.post(
            CREATOR_URL,
            headers=tiktok_headers(account["access_token"]),
            timeout=30,
        )
        payload = response.json()
        return response, payload
    except requests.RequestException as exc:
        return None, {"error": {"code": "network_error", "message": str(exc)}}
    except ValueError:
        return response, {
            "error": {
                "code": "invalid_json",
                "message": "TikTok returned a non-JSON response.",
            }
        }


@app.get("/")
def dashboard():
    conn = db()
    accounts = conn.execute(
        """SELECT open_id,display_name,avatar_url,scope,connected_at
           FROM accounts ORDER BY connected_at DESC"""
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", accounts=accounts)


@app.get("/auth/tiktok/login")
def tiktok_login():
    if not CLIENT_KEY or not CLIENT_SECRET:
        flash(
            "TikTok Sandbox credentials belum dipasang di Environment Variables.",
            "error",
        )
        return redirect(url_for("dashboard"))

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "disable_auto_auth": "1",
    }
    return redirect(AUTH_URL + "?" + urlencode(params))


@app.get("/auth/tiktok/callback")
def tiktok_callback():
    if request.args.get("error"):
        flash(
            "TikTok authorization gagal: "
            + request.args.get(
                "error_description", request.args.get("error", "unknown error")
            ),
            "error",
        )
        return redirect(url_for("dashboard"))

    if (
        not request.args.get("state")
        or request.args.get("state") != session.pop("oauth_state", None)
    ):
        flash(
            "OAuth state tidak cocok. Silakan Connect TikTok lagi.",
            "error",
        )
        return redirect(url_for("dashboard"))

    code = request.args.get("code")
    try:
        response = requests.post(
            TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
            timeout=30,
        )
        data = response.json()
    except Exception as exc:
        flash("Token exchange gagal: " + str(exc), "error")
        return redirect(url_for("dashboard"))

    if not response.ok or "access_token" not in data:
        flash("Token exchange gagal: " + str(data), "error")
        return redirect(url_for("dashboard"))

    token = data["access_token"]
    open_id = data.get("open_id", "")

    try:
        user_response = requests.get(
            USER_URL,
            params={"fields": "open_id,display_name,avatar_url"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        user_payload = user_response.json()
    except Exception as exc:
        flash("Gagal membaca profil TikTok: " + str(exc), "error")
        return redirect(url_for("dashboard"))

    user = user_payload.get("data", {}).get("user", {})

    conn = db()
    conn.execute(
        """INSERT OR REPLACE INTO accounts(
            open_id,display_name,avatar_url,access_token,refresh_token,
            scope,expires_in,connected_at
        ) VALUES(?,?,?,?,?,?,?,?)""",
        (
            open_id,
            user.get("display_name", "TikTok account"),
            user.get("avatar_url", ""),
            token,
            data.get("refresh_token", ""),
            data.get("scope", ""),
            data.get("expires_in", 0),
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()

    flash("TikTok account berhasil terhubung.", "success")
    return redirect(url_for("dashboard"))


@app.route("/create-post/<open_id>", methods=["GET", "POST"])
def create_post(open_id):
    account = get_account(open_id)
    if not account:
        flash("TikTok account tidak ditemukan.", "error")
        return redirect(url_for("dashboard"))

    response, info = creator_info(account)
    creator = info.get("data", {})
    api_error = info.get("error", {})

    if not response or not response.ok or api_error.get("code") not in (None, "", "ok"):
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    if request.method == "GET":
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    # Re-querying Creator Info immediately before posting is intentional.
    # The UI must honor the latest privacy and interaction capabilities.
    privacy_level = request.form.get("privacy_level", "").strip()
    caption = request.form.get("caption", "").strip()
    video = request.files.get("video")

    allowed_privacy = creator.get("privacy_level_options", [])
    if privacy_level not in allowed_privacy:
        flash(
            "Privacy yang dipilih tidak tersedia untuk akun TikTok ini.",
            "error",
        )
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    if not video or not video.filename:
        flash("Pilih file video terlebih dahulu.", "error")
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    ext = os.path.splitext(video.filename.lower())[1]
    if ext not in {".mp4", ".mov", ".webm"}:
        flash("Format video harus MP4, MOV, atau WEBM.", "error")
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    # Read once so size, init request, and upload use identical bytes.
    video_bytes = video.read()
    video_size = len(video_bytes)
    if video_size <= 0:
        flash("File video kosong.", "error")
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    if video_size > MAX_UPLOAD_BYTES:
        flash(
            f"File terlalu besar untuk konfigurasi web ini. Maksimum {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
            "error",
        )
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    max_duration = creator.get("max_video_post_duration_sec")
    # Duration itself is validated by TikTok. The UI can display max_duration
    # from Creator Info; this server does not transcode or inspect media.

    post_info = {
        "title": caption,
        "privacy_level": privacy_level,
        "disable_comment": bool(creator.get("comment_disabled", False)),
        "disable_duet": bool(creator.get("duet_disabled", False)),
        "disable_stitch": bool(creator.get("stitch_disabled", False)),
    }

    # A single chunk is valid for small files. TikTok requires normal chunks
    # to be >=5 MB; the final chunk may be smaller.
    init_payload = {
        "post_info": post_info,
        "source_info": {
            "source": "FILE_UPLOAD",
            "video_size": video_size,
            "chunk_size": video_size,
            "total_chunk_count": 1,
        },
    }

    try:
        init_response = requests.post(
            DIRECT_POST_INIT_URL,
            headers=tiktok_headers(account["access_token"]),
            json=init_payload,
            timeout=60,
        )
        init_data = init_response.json()
    except Exception as exc:
        flash("Gagal menginisialisasi Direct Post: " + str(exc), "error")
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    init_error = init_data.get("error", {})
    if (
        not init_response.ok
        or init_error.get("code") not in (None, "", "ok")
        or not init_data.get("data", {}).get("upload_url")
    ):
        flash("TikTok menolak inisialisasi post: " + str(init_data), "error")
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    upload_url = init_data["data"]["upload_url"]
    publish_id = init_data["data"].get("publish_id", "")
    mime = mimetypes.guess_type(video.filename)[0] or "video/mp4"
    if mime not in {"video/mp4", "video/quicktime", "video/webm"}:
        mime = "video/mp4"

    upload_headers = {
        "Content-Type": mime,
        "Content-Length": str(video_size),
        "Content-Range": f"bytes 0-{video_size - 1}/{video_size}",
    }

    try:
        upload_response = requests.put(
            upload_url,
            headers=upload_headers,
            data=video_bytes,
            timeout=180,
        )
    except requests.RequestException as exc:
        flash("Upload video ke TikTok gagal: " + str(exc), "error")
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    if not upload_response.ok:
        flash(
            f"Upload video ke TikTok gagal (HTTP {upload_response.status_code}): "
            + upload_response.text[:500],
            "error",
        )
        return render_template(
            "create_post.html",
            account=account,
            creator=creator,
            api_error=api_error,
        )

    conn = db()
    conn.execute(
        """INSERT OR REPLACE INTO publish_jobs(
            publish_id,open_id,caption,privacy_level,status,created_at,last_response
        ) VALUES(?,?,?,?,?,?,?)""",
        (
            publish_id,
            open_id,
            caption,
            privacy_level,
            "PROCESSING",
            datetime.utcnow().isoformat(),
            str(init_data),
        ),
    )
    conn.commit()
    conn.close()

    flash(
        "Video berhasil dikirim ke TikTok untuk diproses. "
        "Gunakan tombol Check Status untuk melihat hasil pemrosesan.",
        "success",
    )
    return redirect(
        url_for("publish_status", open_id=open_id, publish_id=publish_id)
    )


@app.route("/publish-status/<open_id>/<path:publish_id>", methods=["GET", "POST"])
def publish_status(open_id, publish_id):
    account = get_account(open_id)
    if not account:
        flash("TikTok account tidak ditemukan.", "error")
        return redirect(url_for("dashboard"))

    try:
        response = requests.post(
            POST_STATUS_URL,
            headers=tiktok_headers(account["access_token"]),
            json={"publish_id": publish_id},
            timeout=30,
        )
        payload = response.json()
    except Exception as exc:
        payload = {
            "error": {"code": "network_error", "message": str(exc)},
            "data": {},
        }

    status = payload.get("data", {}).get("status", "UNKNOWN")
    conn = db()
    conn.execute(
        "UPDATE publish_jobs SET status=?, last_response=? WHERE publish_id=?",
        (status, str(payload), publish_id),
    )
    conn.commit()
    conn.close()

    # This template is optional. If it doesn't exist yet, show a compact
    # browser-readable result so app.py V2 still works immediately.
    try:
        return render_template(
            "publish_status.html",
            account=account,
            publish_id=publish_id,
            result=payload,
            status=status,
        )
    except Exception:
        return {
            "publish_id": publish_id,
            "status": status,
            "result": payload,
            "check_again": url_for(
                "publish_status",
                open_id=open_id,
                publish_id=publish_id,
                _external=True,
            ),
        }


@app.get(f"/{VERIFY_FILENAME}")
def tiktok_url_verification():
    return send_from_directory(
        app.root_path,
        VERIFY_FILENAME,
        mimetype="text/plain",
    )


@app.get("/health")
def health():
    return {"status": "ok", "version": "KelolaTiktok V2"}


@app.errorhandler(413)
def too_large(_error):
    return (
        f"File terlalu besar. Maksimum {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
        413,
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
