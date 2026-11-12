import base64
import datetime
import hmac
import io
import math
import mimetypes
import os
import re
import secrets
import warnings
from decimal import Decimal, InvalidOperation

import psycopg
import qrcode
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from PIL import Image, UnidentifiedImageError
from psycopg.rows import dict_row
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER", os.path.join(app.root_path, "static", "uploads")
)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME")
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_SETTINGS = (
    R2_BUCKET_NAME,
    R2_ACCOUNT_ID,
    R2_ACCESS_KEY_ID,
    R2_SECRET_ACCESS_KEY,
)
if any(R2_SETTINGS) and not all(R2_SETTINGS):
  raise RuntimeError(
      "Les variables R2_BUCKET_NAME, R2_ACCOUNT_ID, R2_ACCESS_KEY_ID et "
      "R2_SECRET_ACCESS_KEY doivent toutes être définies."
  )
R2_ENABLED = all(R2_SETTINGS)
R2_CLIENT = (
    boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name="auto",
    )
    if R2_ENABLED
    else None
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "true").lower() == "true"
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
APP_BASE_URL = os.environ.get(
    "APP_BASE_URL", "https://suivi-stock.onrender.com"
).rstrip("/")
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD_HASH = os.environ.get("APP_PASSWORD_HASH")
PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"

if not app.config["SECRET_KEY"]:
  raise RuntimeError("La variable d'environnement SECRET_KEY doit être définie.")
if len(app.config["SECRET_KEY"]) < 32:
  raise RuntimeError("SECRET_KEY doit contenir au moins 32 caractères.")
if not DATABASE_URL:
  raise RuntimeError("La variable d'environnement DATABASE_URL doit être définie.")

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Connexion - Suivi Inventaire</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        html { -webkit-text-size-adjust: 100%; }
        @media (max-width: 767px) {
            input { font-size: 16px !important; }
            button { min-height: 44px; }
        }
    </style>
</head>
<body class="min-h-screen bg-slate-50 flex items-center justify-center p-4">
    <main class="w-full max-w-sm bg-white rounded-lg shadow p-6">
        <h1 class="text-lg font-bold text-slate-900 mb-5">Connexion au suivi de stock</h1>
        {% if error %}<p role="alert" class="text-sm text-rose-700 mb-4">{{ error }}</p>{% endif %}
        <form method="POST" class="space-y-4">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label class="block text-sm font-medium text-slate-700">
                Identifiant
                <input name="username" autocomplete="username" required class="mt-1 w-full border rounded p-2">
            </label>
            <label class="block text-sm font-medium text-slate-700">
                Mot de passe
                <input type="password" name="password" autocomplete="current-password" required class="mt-1 w-full border rounded p-2">
            </label>
            <button type="submit" class="w-full bg-emerald-900 text-white rounded p-2 font-semibold">Se connecter</button>
        </form>
    </main>
</body>
</html>
"""

def allowed_file(filename):
  return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
  if "/" in filename or "\\" in filename or filename in {".", ".."}:
    abort(404)
  if R2_ENABLED:
    try:
      response = R2_CLIENT.get_object(Bucket=R2_BUCKET_NAME, Key=filename)
      try:
        image_data = response["Body"].read()
      finally:
        response["Body"].close()
      content_type = response.get("ContentType") or mimetypes.guess_type(filename)[0]
      if not content_type:
        content_type = "application/octet-stream"
      image_response = app.response_class(
          image_data,
          mimetype=content_type,
          direct_passthrough=False,
      )
      image_response.headers["Cache-Control"] = "private, max-age=3600"
      return image_response
    except ClientError as error:
      error_code = error.response.get("Error", {}).get("Code")
      status_code = error.response.get("ResponseMetadata", {}).get(
          "HTTPStatusCode"
      )
      if error_code not in {"NoSuchKey", "NotFound", "404"} and status_code != 404:
        app.logger.exception("R2 image retrieval failed for %s", filename)
        abort(502, description="La photo ne peut pas être récupérée depuis R2.")
      local_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
      if not os.path.isfile(local_path):
        abort(404)
      try:
        with open(local_path, "rb") as image_file:
          image_data = image_file.read()
        R2_CLIENT.put_object(
            Bucket=R2_BUCKET_NAME,
            Key=filename,
            Body=image_data,
            ContentType=mimetypes.guess_type(filename)[0] or "application/octet-stream",
        )
      except (OSError, BotoCoreError):
        app.logger.exception("Could not migrate local image to R2: %s", filename)
        abort(502, description="La photo locale n'a pas pu être transférée vers R2.")
      local_response = app.response_class(
          image_data,
          mimetype=mimetypes.guess_type(filename)[0] or "application/octet-stream",
          direct_passthrough=False,
      )
      local_response.headers["Cache-Control"] = "private, max-age=3600"
      return local_response
    except BotoCoreError:
      app.logger.exception("R2 image retrieval failed for %s", filename)
      abort(502, description="La photo ne peut pas être récupérée depuis R2.")
  return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


def save_uploaded_image(upload):
  if not upload or not upload.filename:
    return None
  if not allowed_file(upload.filename):
    abort(400, description="Format d'image non autorisé.")
  image_data = upload.read()
  try:
    with warnings.catch_warnings():
      warnings.simplefilter("error", Image.DecompressionBombWarning)
      image = Image.open(io.BytesIO(image_data))
      image_format = image.format
      image.verify()
  except (
      UnidentifiedImageError,
      OSError,
      Image.DecompressionBombError,
      Image.DecompressionBombWarning,
  ):
    abort(400, description="Le fichier envoyé n'est pas une image valide.")
  expected_formats = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP"}
  extension = upload.filename.rsplit(".", 1)[1].lower()
  if image_format != expected_formats[extension]:
    abort(400, description="L'extension ne correspond pas au format de l'image.")
  filename = f"art_{secrets.token_hex(8)}_{secure_filename(upload.filename)}"
  if R2_ENABLED:
    try:
      R2_CLIENT.put_object(
          Bucket=R2_BUCKET_NAME,
          Key=filename,
          Body=image_data,
          ContentType=f"image/{'jpeg' if extension in {'jpg', 'jpeg'} else extension}",
      )
    except BotoCoreError:
      app.logger.exception("R2 image upload failed.")
      abort(502, description="La photo n'a pas pu être enregistrée dans R2.")
    return filename
  with open(os.path.join(app.config["UPLOAD_FOLDER"], filename), "wb") as image_file:
    image_file.write(image_data)
  return filename


def article_qr_code_data(article_url):
  qr_code = qrcode.QRCode(
      version=None,
      error_correction=qrcode.constants.ERROR_CORRECT_M,
      box_size=10,
      border=4,
  )
  qr_code.add_data(article_url)
  qr_code.make(fit=True)
  image = qr_code.make_image(fill_color="black", back_color="white")
  image_buffer = io.BytesIO()
  image.save(image_buffer, format="PNG")
  encoded_image = base64.b64encode(image_buffer.getvalue()).decode("ascii")
  return f"data:image/png;base64,{encoded_image}"


def form_integer(field, default=None, minimum=None):
  value = request.form.get(field)
  if value in (None, ""):
    if default is not None:
      return default
    abort(400, description=f"Le champ {field} est obligatoire.")
  try:
    result = int(value)
  except (TypeError, ValueError):
    abort(400, description=f"Le champ {field} doit être un nombre entier.")
  if minimum is not None and result < minimum:
    abort(400, description=f"Le champ {field} doit être supérieur ou égal à {minimum}.")
  return result


def optional_integer(value, field):
  if value in (None, ""):
    return None
  try:
    result = int(value)
  except (TypeError, ValueError):
    abort(400, description=f"Le champ {field} doit être un nombre entier.")
  if result < 1:
    abort(400, description=f"Le champ {field} doit être supérieur à zéro.")
  return result


def form_price(field="price"):
  value = request.form.get(field, "0")
  try:
    result = float(value or 0)
  except (TypeError, ValueError):
    abort(400, description="Le prix doit être un nombre valide.")
  if not math.isfinite(result) or result < 0:
    abort(400, description="Le prix doit être positif ou nul.")
  return result


def is_usable_password_hash(password_hash):
  if not isinstance(password_hash, str):
    return False
  parts = password_hash.split("$", 2)
  if len(parts) != 3 or not parts[1] or not re.fullmatch(r"[0-9a-f]+", parts[2]):
    return False
  method_parts = parts[0].split(":")
  if method_parts[0] == "pbkdf2":
    return (
        len(method_parts) == 3
        and method_parts[1] == "sha256"
        and method_parts[2].isdigit()
    )
  if method_parts[0] == "scrypt":
    return len(method_parts) == 4 and all(part.isdigit() for part in method_parts[1:])
  return False


def verify_password(password_hash, password):
  try:
    return check_password_hash(password_hash, password)
  except (TypeError, ValueError) as error:
    app.logger.warning("Rejected malformed stored password hash: %s", error)
    return False


def hash_password(password):
  return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def csrf_token():
  token = session.get("_csrf_token")
  if token is None:
    token = secrets.token_urlsafe(32)
    session["_csrf_token"] = token
  return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_requests():
  if request.endpoint != "login" and not session.get("authenticated"):
    next_url = request.full_path if request.query_string else request.path
    return redirect(url_for("login", next=next_url))
  if request.endpoint != "login" and session.get("authenticated"):
    cur = get_db().cursor()
    cur.execute(
        "SELECT id, username, role FROM users WHERE id = %s AND active = TRUE",
        (session.get("user_id"),),
    )
    g.current_user = cur.fetchone()
    cur.close()
    if g.current_user is None:
      session.clear()
      return redirect(url_for("login"))
  if request.method == "POST":
    submitted_token = request.form.get("csrf_token", "")
    if not submitted_token or not hmac.compare_digest(submitted_token, csrf_token()):
      abort(400, description="Jeton CSRF invalide ou expiré.")


@app.route("/login", methods=["GET", "POST"])
def login():
  error = None
  if request.method == "POST":
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    cur = get_db().cursor()
    cur.execute(
        "SELECT id, username, password_hash FROM users WHERE username = %s AND active = TRUE",
        (username,),
    )
    user = cur.fetchone()
    cur.close()
    if user and verify_password(user["password_hash"], password):
      if not user["password_hash"].startswith(PASSWORD_HASH_METHOD + "$"):
        cur = get_db().cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (hash_password(password), user["id"]),
        )
        get_db().commit()
        cur.close()
      session.clear()
      session["authenticated"] = True
      session["user_id"] = user["id"]
      csrf_token()
      next_url = request.args.get("next", "")
      if next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)
      return redirect(url_for("home"))
    error = "Identifiant ou mot de passe incorrect."
  return render_template_string(LOGIN_TEMPLATE, error=error, csrf_token=csrf_token())


@app.route("/logout", methods=["POST"])
def logout():
  session.clear()
  return redirect(url_for("login"))


def require_admin():
  current_user = getattr(g, "current_user", None)
  if not current_user or current_user["role"] != "admin":
    abort(403)


def get_db():
  if "db" not in g:
    g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
  return g.db


@app.teardown_appcontext
def close_connection(_exception):
  db = g.pop("db", None)
  if db is not None:
    db.close()


def init_db():
  if not DATABASE_URL:
    return
  conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
  conn.autocommit = True
  cursor = conn.cursor(row_factory=dict_row)
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS locations (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS equipment (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS articles (
            id SERIAL PRIMARY KEY,
            reference TEXT,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL DEFAULT 0.0,
            is_estimated_price INTEGER DEFAULT 0,
            min_threshold INTEGER DEFAULT 2,
            supplier TEXT,
            invoice_number TEXT,
            entry_date DATE,
            location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL,
            equipment_id INTEGER REFERENCES equipment(id) ON DELETE SET NULL,
            image_filename TEXT
        );
        CREATE TABLE IF NOT EXISTS movements (
            id SERIAL PRIMARY KEY,
            article_id INTEGER REFERENCES articles(id) ON DELETE SET NULL,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL,
            unit_price_estimated BOOLEAN,
            supplier TEXT,
            invoice_number TEXT,
            reason TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
  cursor.execute("SELECT pg_advisory_lock(73401219078123::bigint)")
  try:
    cursor.execute("SELECT COUNT(*) AS count FROM users")
    if cursor.fetchone()["count"] == 0:
      if not APP_PASSWORD_HASH:
        raise RuntimeError(
            "La base ne contient aucun utilisateur. Définissez APP_PASSWORD_HASH "
            "pour initialiser le compte administrateur."
        )
      if not is_usable_password_hash(APP_PASSWORD_HASH):
        raise RuntimeError(
            "APP_PASSWORD_HASH est invalide. Générez-le avec Werkzeug en utilisant "
            "la méthode pbkdf2:sha256."
        )
      if not APP_USERNAME.strip():
        raise RuntimeError("APP_USERNAME ne peut pas être vide.")
      cursor.execute(
          """
              INSERT INTO users (username, password_hash, role)
              VALUES (%s, %s, 'admin')
              ON CONFLICT (username) DO NOTHING
          """,
          (APP_USERNAME.strip().lower(), APP_PASSWORD_HASH),
      )
    elif APP_PASSWORD_HASH and APP_USERNAME.strip():
      cursor.execute(
          "SELECT id, password_hash FROM users WHERE username = %s AND role = 'admin'",
          (APP_USERNAME.strip().lower(),),
      )
      admin_user = cursor.fetchone()
      if (
          admin_user
          and not is_usable_password_hash(admin_user["password_hash"])
          and is_usable_password_hash(APP_PASSWORD_HASH)
      ):
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (APP_PASSWORD_HASH, admin_user["id"]),
        )
        app.logger.warning(
            "Replaced malformed password hash for the configured administrator."
        )
  finally:
    cursor.execute("SELECT pg_advisory_unlock(73401219078123::bigint)")
  cursor.execute("""
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS min_threshold INTEGER DEFAULT 2;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS supplier TEXT;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS invoice_number TEXT;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS entry_date DATE;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS supplier TEXT;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS invoice_number TEXT;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS unit_price REAL;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS unit_price_estimated BOOLEAN;
        CREATE INDEX IF NOT EXISTS idx_movements_date_id
            ON movements (date DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_movements_article_date_id
            ON movements (article_id, date DESC, id DESC);
    """)
  cursor.execute("SELECT pg_advisory_lock(73401219078123::bigint)")
  try:
    cursor.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'movements_article_id_fkey'
                  AND conrelid = 'movements'::regclass
                  AND confdeltype <> 'n'
            ) THEN
                ALTER TABLE movements DROP CONSTRAINT movements_article_id_fkey;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'movements_article_id_fkey'
                  AND conrelid = 'movements'::regclass
            ) THEN
                ALTER TABLE movements ADD CONSTRAINT movements_article_id_fkey
                    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE SET NULL;
            END IF;
        END;
        $$;
    """)
  finally:
    cursor.execute("SELECT pg_advisory_unlock(73401219078123::bigint)")
  cursor.close()
  conn.close()


with app.app_context():
  init_db()


# --- LAYOUT UNIFIÉ & CHARTE GRAPHIQUE (Vert Sapin Naturel) ---

LAYOUT_HEADER = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0b3d2c">
    <title>Gestion & Suivi de Stock</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            .no-print { display: none !important; }
            body { background: white !important; font-size: 11px; }
            .print-table { border: 1px solid #CBD5E1 !important; }
            .print-table { min-width: 0 !important; }
            .page-break { page-break-before: always; }
            .qr-print-page { display: block !important; min-height: 0 !important; }
            .qr-print-page > header, .qr-print-page > footer { display: none !important; }
            .qr-print-page > main {
                width: 85mm !important;
                height: 55mm !important;
                max-width: none !important;
                margin: 0 !important;
                padding: 0 !important;
            }
            .qr-print-page > main > div { height: 100%; margin: 0 !important; }
            .qr-print-page > main > div > :not(.article-qr-card) { display: none !important; }
            .article-qr-card {
                box-sizing: border-box !important;
                display: flex !important;
                flex-direction: row !important;
                align-items: center !important;
                justify-content: center !important;
                gap: 4mm !important;
                width: 85mm !important;
                height: 55mm !important;
                padding: 4mm !important;
                border: 0.3mm solid #CBD5E1 !important;
                border-radius: 2mm !important;
                box-shadow: none !important;
                text-align: left !important;
                overflow: hidden !important;
            }
            .article-qr-code {
                flex: none !important;
                width: 36mm !important;
                height: 36mm !important;
                margin: 0 !important;
                padding: 0 !important;
                border: 0 !important;
            }
            .article-qr-code img { width: 36mm !important; height: 36mm !important; }
            .article-qr-details { min-width: 0; overflow-wrap: anywhere; }
            .article-qr-details h2 { font-size: 12pt !important; line-height: 1.15 !important; }
            .article-qr-details .article-reference { font-size: 9pt !important; }
            .article-qr-details .qr-scan-hint { margin-top: 2mm !important; font-size: 7pt !important; }
        }
        .bg-forest { background-color: #0b3d2c; }
        .bg-forest-light { background-color: #124e38; }
        .border-forest { border-color: #0b3d2c; }
        .text-forest { color: #0b3d2c; }
        html { -webkit-text-size-adjust: 100%; scroll-behavior: smooth; }
        body { overflow-x: hidden; }
        input, select, textarea, button { max-width: 100%; }
        button, a, input[type="checkbox"], input[type="file"] { touch-action: manipulation; }
        input[type="checkbox"] { width: 1.25rem; height: 1.25rem; }
        .print-table { min-width: 980px; }
        .overflow-x-auto { -webkit-overflow-scrolling: touch; }
        @media (max-width: 767px) {
            input:not([type="checkbox"]):not([type="file"]), select, textarea {
                font-size: 16px !important;
            }
            button, input[type="submit"], select { min-height: 44px; }
            .print-table { min-width: 920px; }
        }
    </style>
</head>
<body class="bg-slate-50 text-slate-800 font-sans antialiased min-h-screen flex flex-col {{ 'qr-print-page' if print_qr_page|default(false) else '' }}">

    <!-- Header / Navbar Principal -->
    <header class="bg-forest text-white shadow-md border-b border-emerald-900 no-print">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex flex-col gap-3 py-3 md:flex-row md:items-center md:justify-between md:h-16 md:py-0">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-forest-light rounded-lg flex items-center justify-center font-bold text-emerald-300 border border-emerald-700 shadow-inner">
                        🌿
                    </div>
                    <div>
                        <a href="/" class="text-sm font-extrabold tracking-wider uppercase text-white block">SUIVI INVENTAIRE</a>
                        <span class="text-[10px] text-emerald-300 font-medium tracking-wide">CAPITAL IMMOBILISÉ : {{ "%.2f"|format(total_stock_value or 0) }} €</span>
                    </div>
                </div>

                <nav class="grid grid-cols-2 gap-1 sm:flex sm:flex-wrap sm:items-center sm:justify-end sm:gap-1">
                    <span class="col-span-2 text-center px-2 py-1 text-[10px] text-emerald-200 sm:col-span-1">{{ g.current_user.username }}</span>
                    <a href="/entry" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'entry' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>✏️</span> Entrée / Sortie
                    </a>
                    <a href="/stock" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'stock' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>📊</span> Suivi & Rapport
                    </a>
                    <a href="/movements" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'movements' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>🧾</span> Mouvements
                    </a>
                    <a href="/monthly-close" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'monthly_close' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>📅</span> Clôture mensuelle
                    </a>
                    <a href="/settings" class="min-h-11 px-2 sm:px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center justify-center gap-1.5 {% if active_page == 'settings' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>⚙️</span> Réglages
                    </a>
                    <form action="{{ url_for('logout') }}" method="POST" class="col-span-2 sm:col-span-1">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <button class="w-full min-h-11 px-3 py-2 rounded-md text-xs font-semibold text-emerald-100 hover:bg-forest-light">Déconnexion</button>
                    </form>
                </nav>
            </div>
        </div>
    </header>

    <main class="flex-grow max-w-7xl w-full min-w-0 mx-auto p-3 sm:p-6 lg:p-8">
"""

LAYOUT_FOOTER = """
    </main>
    <footer class="bg-forest text-emerald-300/70 text-[11px] py-4 border-t border-emerald-900 text-center no-print mt-auto">
        Système de Gestion de Stock & Operations | Facility Management
    </footer>
</body>
</html>
"""

# --- 1. PAGE DE SAISIE DE DONNÉES ---
ENTRY_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-5xl mx-auto space-y-6">
        <div class="rounded-xl bg-gradient-to-r from-emerald-950 to-emerald-800 p-5 sm:p-7 text-white shadow-md">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-200">Gestion des mouvements</p>
            <h1 class="mt-1 text-2xl sm:text-3xl font-extrabold">Entrée et sortie de stock</h1>
            <p class="mt-2 max-w-2xl text-sm text-emerald-100">Choisissez l’opération à effectuer. Chaque mouvement est enregistré dans l’historique de l’inventaire.</p>
            <div class="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <a href="{% if preselected_article_found %}#existing-entry{% else %}#stock-entry{% endif %}" class="flex min-h-14 items-center justify-between gap-3 rounded-lg bg-white px-4 py-3 text-left font-bold text-emerald-950 shadow transition hover:bg-emerald-50 focus:outline-none focus:ring-4 focus:ring-emerald-300">
                    <span class="flex items-center gap-3"><span class="flex h-9 w-9 items-center justify-center rounded-full bg-emerald-100 text-xl" aria-hidden="true">＋</span>Entrée de Stock</span>
                    <span aria-hidden="true">↓</span>
                </a>
                <a href="#stock-exit" class="flex min-h-14 items-center justify-between gap-3 rounded-lg border border-emerald-400 bg-emerald-900/50 px-4 py-3 text-left font-bold text-white transition hover:bg-emerald-900 focus:outline-none focus:ring-4 focus:ring-emerald-300">
                    <span class="flex items-center gap-3"><span class="flex h-9 w-9 items-center justify-center rounded-full bg-amber-300 text-xl text-amber-950" aria-hidden="true">−</span>Sortie de Stock</span>
                    <span aria-hidden="true">↓</span>
                </a>
            </div>
        </div>

        {% if preselected_article_found %}
        <section id="operation-choice" class="scroll-mt-4 rounded-xl border border-sky-200 bg-white p-4 shadow-sm sm:p-6">
            <p class="text-xs font-bold uppercase tracking-wide text-sky-800">Article scanné</p>
            <h2 class="mt-1 text-lg font-extrabold text-slate-900">{{ selected_article.name }}</h2>
            <p class="text-sm text-slate-600">Référence : {{ selected_article.reference or 'Non renseignée' }} · Stock disponible : {{ selected_article.quantity }}</p>
            <p class="mt-4 text-sm font-semibold text-slate-800">Quelle opération souhaitez-vous effectuer ?</p>
            <div class="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                <a href="#existing-entry" class="flex min-h-14 items-center justify-center gap-2 rounded-lg bg-emerald-800 px-4 py-3 text-center font-bold text-white hover:bg-emerald-900">
                    <span aria-hidden="true">＋</span> Entrée de stock
                </a>
                <a href="#stock-exit" class="flex min-h-14 items-center justify-center gap-2 rounded-lg bg-amber-600 px-4 py-3 text-center font-bold text-white hover:bg-amber-700">
                    <span aria-hidden="true">−</span> Sortie de stock
                </a>
            </div>
        </section>

        <section id="existing-entry" class="scroll-mt-4 overflow-hidden rounded-xl border border-emerald-200 bg-white shadow-sm">
            <div class="border-b border-emerald-100 bg-emerald-50 p-4 sm:p-6">
                <h2 class="text-lg font-extrabold text-emerald-950">Entrée de Stock</h2>
                <p class="mt-1 text-sm text-emerald-900">Ajouter une quantité à l’article scanné.</p>
            </div>
            <form action="{{ url_for('movement_entry') }}" method="POST" class="space-y-4 p-4 sm:p-6">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="hidden" name="article_id" value="{{ selected_article.id }}">
                <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <label class="block text-sm font-semibold text-slate-700">
                        Quantité à ajouter *
                        <input type="number" name="qty" value="1" min="1" step="1" required class="mt-1 w-full rounded border border-slate-300 p-2.5">
                    </label>
                    <label class="block text-sm font-semibold text-slate-700">
                        Tarif unitaire (€) *
                        <input type="number" name="price" value="{{ '%.2f'|format(selected_article.price or 0) }}" min="0" step="0.01" required class="mt-1 w-full rounded border border-slate-300 p-2.5">
                    </label>
                    <label class="block text-sm font-semibold text-slate-700">
                        Fournisseur
                        <input type="text" name="supplier" value="{{ selected_article.supplier or '' }}" placeholder="Nom du fournisseur" class="mt-1 w-full rounded border border-slate-300 p-2.5">
                    </label>
                    <label class="block text-sm font-semibold text-slate-700">
                        N° de facture (facultatif)
                        <input type="text" name="invoice_number" placeholder="Ex. FAC-2026-99" class="mt-1 w-full rounded border border-slate-300 p-2.5">
                    </label>
                </div>
                <button type="submit" class="min-h-12 w-full rounded-lg bg-emerald-800 px-4 py-3 text-sm font-bold text-white hover:bg-emerald-900">Enregistrer l’Entrée de Stock</button>
            </form>
        </section>
        {% endif %}

        {% if not preselected_article_found %}
        <section id="stock-entry" class="scroll-mt-4 overflow-hidden rounded-xl border border-emerald-200 bg-white shadow-sm">
            <div class="flex items-start gap-4 border-b border-emerald-100 bg-emerald-50 p-4 sm:p-6">
                <span class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-emerald-700 text-2xl font-bold text-white" aria-hidden="true">＋</span>
                <div>
                    <h2 class="text-lg font-extrabold text-emerald-950 sm:text-xl">Entrée de Stock</h2>
                    <p class="mt-1 text-sm text-emerald-900">Ajoutez un nouvel article à l’inventaire et renseignez sa quantité initiale.</p>
                </div>
            </div>
            <div class="p-4 sm:p-6">
                <div class="space-y-4">
                    
                    <form action="/add" method="POST" enctype="multipart/form-data" class="space-y-4">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div class="md:col-span-2">
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Nom de l'article *</label>
                                <input type="text" name="name" required placeholder="ex: Disjoncteur 16A" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                                <input type="text" name="reference" placeholder="ex: REF-8840" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité initiale *</label>
                                <input type="number" name="quantity" value="1" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Stock Mini (Alerte) *</label>
                                <input type="number" name="min_threshold" value="2" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold text-rose-600">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Prix unitaire (€)</label>
                                <input type="number" step="0.01" name="price" value="0.00" required class="w-full text-xs p-2.5 border border-slate-300 rounded">
                            </div>
                            <div class="flex items-end pb-2">
                                <label class="flex items-center gap-2 text-xs text-slate-600 cursor-pointer">
                                    <input type="checkbox" name="is_estimated_price" value="1" class="rounded border-slate-300 text-emerald-800">
                                    <span>Prix estimé</span>
                                </label>
                            </div>
                        </div>

                        <!-- Champs Fournisseur, Facture & Date d'entrée -->
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-emerald-50/40 p-3 rounded border border-emerald-100">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Fournisseur</label>
                                <input type="text" name="supplier" placeholder="ex: Rexel, Leroy Merlin..." class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">N° de facture</label>
                                <input type="text" name="invoice_number" placeholder="ex: FAC-2026-99" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Date d'entrée</label>
                                <input type="date" name="entry_date" value="{{ today_date }}" required class="w-full text-xs p-2 border border-slate-300 rounded bg-white font-medium">
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Emplacement du stock</label>
                                <select name="location_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                                    <option value="">-- Sélectionner un lieu --</option>
                                    {% for loc in locations %}
                                    <option value="{{ loc.id }}">{{ loc.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Équipement associé</label>
                                <select name="equipment_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                                    <option value="">-- Sélectionner une machine --</option>
                                    {% for eq in equipment %}
                                    <option value="{{ eq.id }}">{{ eq.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                        </div>

                        <div>
                            <label for="article-photo" class="mb-2 block text-sm font-bold text-slate-800">Photo de l’article <span class="font-normal text-slate-500">(facultatif)</span></label>
                            <input id="article-photo" type="file" name="photo" accept="image/png,image/jpeg,image/webp" class="peer sr-only">
                            <label for="article-photo" class="flex min-h-28 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-emerald-500 bg-emerald-50/70 px-4 py-5 text-center transition hover:border-emerald-700 hover:bg-emerald-50 peer-focus-visible:outline-none peer-focus-visible:ring-4 peer-focus-visible:ring-emerald-200">
                                <span class="flex h-11 w-11 items-center justify-center rounded-full bg-white text-2xl shadow-sm" aria-hidden="true">📷</span>
                                <span class="font-bold text-emerald-950">Ajouter une photo</span>
                                <span class="text-xs text-slate-600">Touchez pour choisir une image · JPG, PNG ou WEBP · 5 Mo maximum</span>
                            </label>
                            <div id="article-photo-preview" class="mt-3 hidden items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
                                <img id="article-photo-image" alt="Aperçu de la photo de l’article" class="h-16 w-16 rounded-md object-cover">
                                <span id="article-photo-name" class="min-w-0 break-all text-sm font-medium text-slate-700"></span>
                            </div>
                        </div>

                        <button type="submit" class="w-full min-h-12 rounded-lg bg-emerald-800 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-emerald-900">
                            Enregistrer l’Entrée de Stock
                        </button>
                    </form>
                </div>
            </div>
        </section>
        {% endif %}

        <section id="stock-exit" class="scroll-mt-4 overflow-hidden rounded-xl border border-amber-200 bg-white shadow-sm">
            <div class="flex items-start gap-4 border-b border-amber-100 bg-amber-50 p-4 sm:p-6">
                <span class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-amber-500 text-2xl font-bold text-amber-950" aria-hidden="true">−</span>
                <div>
                    <h2 class="text-lg font-extrabold text-amber-950 sm:text-xl">Sortie de Stock</h2>
                    <p class="mt-1 text-sm text-amber-900">Enregistrez le matériel prélevé et indiquez la quantité ainsi que le motif.</p>
                </div>
            </div>
            <div class="p-4 sm:p-6">
                <div class="space-y-4">

                    <form action="/movement_exit" method="POST" class="space-y-4">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <div class="rounded-lg border border-amber-200 bg-amber-50 p-4">
                            <p class="text-sm font-bold text-amber-950">Scanner le QR code de l’article</p>
                            <p class="mt-1 text-xs text-amber-900">Autorisez l’accès à la caméra, puis placez le QR code dans le cadre. Vous pouvez aussi choisir l’article dans la liste ci-dessous.</p>
                            <button type="button" id="start-qr-scanner" class="mt-3 min-h-11 rounded-lg bg-amber-700 px-4 py-2 text-sm font-bold text-white hover:bg-amber-800">📷 Scanner un QR code</button>
                            <div id="qr-reader" class="mt-3 hidden max-w-md overflow-hidden rounded-lg bg-black">
                                <video id="qr-video" class="aspect-video w-full object-cover" autoplay muted playsinline></video>
                            </div>
                            <p id="qr-scan-status" class="mt-2 text-sm text-slate-700" role="status" aria-live="polite"></p>
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Article à prélever *</label>
                            <select id="exit-article-id" name="article_id" required class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                                <option value="">-- Choisir une pièce --</option>
                                {% for item in articles %}
                                <option value="{{ item.id }}" {% if preselected_article_id == item.id %}selected{% endif %}>{{ item.name }} (Réf: {{ item.reference or 'N/C' }}) | Qte dispo: {{ item.quantity }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        {% if preselected_article_id and not preselected_article_found %}
                        <p class="rounded-lg bg-rose-50 p-3 text-sm text-rose-800" role="alert">Cet article n’existe plus dans l’inventaire. Vérifiez le QR code ou choisissez un article dans la liste.</p>
                        {% endif %}

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité sortie *</label>
                                <input id="exit-quantity" type="number" name="qty" value="1" min="1" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Motif / Intervenant *</label>
                                <input type="text" name="reason" required placeholder="ex: Dépannage pompe" class="w-full text-xs p-2.5 border border-slate-300 rounded">
                            </div>
                        </div>

                        <button type="submit" class="w-full min-h-12 rounded-lg bg-amber-600 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-amber-700">
                            Enregistrer la Sortie de Stock
                        </button>
                    </form>
                </div>
            </div>
        </section>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>
    <script>
        (() => {
            const input = document.getElementById("article-photo");
            const preview = document.getElementById("article-photo-preview");
            const image = document.getElementById("article-photo-image");
            const filename = document.getElementById("article-photo-name");
            if (!input) return;
            let previewUrl = null;
            input.addEventListener("change", () => {
                if (previewUrl) URL.revokeObjectURL(previewUrl);
                const file = input.files && input.files[0];
                if (!file) {
                    preview.classList.add("hidden");
                    preview.classList.remove("flex");
                    image.removeAttribute("src");
                    filename.textContent = "";
                    return;
                }
                previewUrl = URL.createObjectURL(file);
                image.src = previewUrl;
                filename.textContent = file.name;
                preview.classList.remove("hidden");
                preview.classList.add("flex");
            });
        })();

        {% if start_exit_mode %}
        window.addEventListener("load", () => {
            document.getElementById("stock-exit").scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
            document.getElementById("exit-quantity").focus({ preventScroll: true });
        });
        {% elif start_entry_mode %}
        window.addEventListener("load", () => {
            document.getElementById("existing-entry").scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
            document.querySelector('#existing-entry input[name="qty"]').focus({ preventScroll: true });
        });
        {% elif start_choice_mode %}
        window.addEventListener("load", () => {
            document.getElementById("operation-choice").scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        });
        {% endif %}

        (() => {
            const startButton = document.getElementById("start-qr-scanner");
            const reader = document.getElementById("qr-reader");
            const video = document.getElementById("qr-video");
            const status = document.getElementById("qr-scan-status");
            const articleSelect = document.getElementById("exit-article-id");
            const canvas = document.createElement("canvas");
            const context = canvas.getContext("2d", { willReadFrequently: true });
            let mediaStream = null;
            let animationFrame = null;
            let scanning = false;
            let lastInvalidText = "";

            const stopScanner = () => {
                scanning = false;
                if (animationFrame !== null) {
                    window.cancelAnimationFrame(animationFrame);
                    animationFrame = null;
                }
                if (mediaStream) {
                    mediaStream.getTracks().forEach((track) => track.stop());
                    mediaStream = null;
                }
                video.pause();
                video.srcObject = null;
                reader.classList.add("hidden");
            };

            const scanFrame = () => {
                if (!scanning) return;
                if (video.readyState === HTMLMediaElement.HAVE_ENOUGH_DATA) {
                    canvas.width = video.videoWidth;
                    canvas.height = video.videoHeight;
                    context.drawImage(video, 0, 0, canvas.width, canvas.height);
                    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
                    const result = window.jsQR(
                        imageData.data,
                        imageData.width,
                        imageData.height,
                        { inversionAttempts: "dontInvert" }
                    );
                    if (result) {
                        let articleId = null;
                        const legacyMatch = result.data.match(/^STOCK:(\\d+)$/i);
                        if (legacyMatch) {
                            articleId = legacyMatch[1];
                        } else {
                            try {
                                const scannedUrl = new URL(result.data);
                                const scannedId = scannedUrl.searchParams.get("article_id") || "";
                                if (
                                    scannedUrl.origin === window.location.origin
                                    && scannedUrl.pathname === "/entry"
                                    && ["choose", "entry", "exit"].includes(
                                        scannedUrl.searchParams.get("mode")
                                    )
                                    && /^\\d+$/.test(scannedId)
                                ) {
                                    articleId = scannedId;
                                }
                            } catch (error) {
                                articleId = null;
                            }
                        }
                        if (!articleId) {
                            if (lastInvalidText !== result.data) {
                                status.textContent = "Ce QR code ne correspond pas à un article de cette application.";
                                lastInvalidText = result.data;
                            }
                        } else {
                            const option = Array.from(articleSelect.options).find(
                                (item) => item.value === articleId
                            );
                            if (!option) {
                                status.textContent = "Article introuvable. Actualisez la page puis réessayez.";
                            } else {
                                articleSelect.value = articleId;
                                status.textContent = "Article sélectionné : " + option.text;
                                stopScanner();
                                startButton.textContent = "📷 Scanner un autre article";
                                document.getElementById("exit-quantity").focus();
                                document.getElementById("stock-exit").scrollIntoView({ behavior: "smooth" });
                                return;
                            }
                        }
                    }
                }
                animationFrame = window.requestAnimationFrame(scanFrame);
            };

            startButton.addEventListener("click", async () => {
                if (scanning) {
                    stopScanner();
                    startButton.textContent = "📷 Reprendre le scan";
                    status.textContent = "Scanner arrêté.";
                    return;
                }
                if (!window.jsQR) {
                    status.textContent = "Le module de lecture QR n’a pas pu être chargé. Vérifiez votre connexion Internet ou choisissez l’article dans la liste.";
                    return;
                }
                if (!window.isSecureContext) {
                    status.textContent = "La caméra nécessite une connexion HTTPS. Ouvrez l’application avec son adresse sécurisée.";
                    return;
                }
                if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                    status.textContent = "Ce navigateur ne permet pas l’accès à la caméra. Choisissez l’article dans la liste.";
                    return;
                }

                reader.classList.remove("hidden");
                status.textContent = "Initialisation de la caméra…";
                try {
                    mediaStream = await navigator.mediaDevices.getUserMedia({
                        audio: false,
                        video: { facingMode: { ideal: "environment" } }
                    });
                    video.srcObject = mediaStream;
                    await video.play();
                    scanning = true;
                    lastInvalidText = "";
                    startButton.textContent = "Arrêter le scan";
                    status.textContent = "Pointez la caméra vers le QR code de l’article.";
                    animationFrame = window.requestAnimationFrame(scanFrame);
                } catch (error) {
                    stopScanner();
                    status.textContent = "Accès à la caméra impossible. Vérifiez les autorisations de Safari ou choisissez l’article dans la liste. Détail : " + String(error);
                }
            });
            window.addEventListener("pagehide", stopScanner);
        })();
    </script>
"""
    + LAYOUT_FOOTER
)

# --- 2. PAGE DE SUIVI DES DONNÉES ET INVENTAIRE PAR LIEU (Corrigé avec group['items']) ---
STOCK_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="space-y-6">
        <div class="bg-forest text-white rounded-lg p-4 sm:p-5 shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border border-emerald-900">
            <div>
                <span class="text-[11px] font-semibold uppercase tracking-wider text-emerald-200">Valeur totale de l'inventaire</span>
                <div class="text-2xl font-extrabold text-white mt-0.5">{{ "%.2f"|format(total_stock_value) }} €</div>
            </div>
            <div class="flex gap-2 no-print">
                <button onclick="window.print()" class="bg-forest-light hover:bg-emerald-900 text-xs font-semibold px-4 py-2 rounded border border-emerald-700 text-white transition">
                    🖨️ Imprimer / PDF
                </button>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm no-print">
            <label class="block text-xs font-semibold text-slate-700 mb-2">Recherche rapide d’article</label>
            <form method="GET" action="/stock" class="grid grid-cols-1 md:grid-cols-6 gap-3">
                <input type="search" name="search" value="{{ search_query or '' }}" aria-label="Rechercher par mot-clé ou référence" placeholder="Nom, mot-clé ou référence…" class="md:col-span-2 text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                <select name="loc_filter" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="">Tous les emplacements</option>
                    {% for loc in locations %}
                    <option value="{{ loc.id }}" {% if current_loc == loc.id %}selected{% endif %}>{{ loc.name }}</option>
                    {% endfor %}
                </select>
                <select name="eq_filter" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="">Tous les équipements</option>
                    {% for eq in equipment %}
                    <option value="{{ eq.id }}" {% if current_eq == eq.id %}selected{% endif %}>{{ eq.name }}</option>
                    {% endfor %}
                </select>
                <select name="stock_status" aria-label="Filtrer par disponibilité" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="" {% if current_stock_status != 'out' %}selected{% endif %}>Tous les stocks</option>
                    <option value="out" {% if current_stock_status == 'out' %}selected{% endif %}>En rupture (quantité zéro)</option>
                </select>
                <div class="flex gap-2">
                    <button type="submit" class="flex-1 bg-forest text-white text-xs font-semibold py-2 rounded hover:bg-forest-light transition">Filtrer</button>
                    {% if search_query or current_loc or current_eq or current_stock_status %}
                    <a href="/stock" class="px-3 py-2 text-xs bg-slate-100 text-slate-600 rounded hover:bg-slate-200 flex items-center">Effacer</a>
                    {% endif %}
                </div>
            </form>
            {% if search_query or current_stock_status %}
            <p class="mt-3 text-xs text-slate-600" role="status" aria-live="polite">
                {{ matched_article_count }} article(s) correspondant(s){% if search_query %} à « {{ search_query }} »{% endif %}{% if current_stock_status == 'out' %} en rupture{% endif %} —
                <strong class="text-emerald-800">{{ in_stock_count }} article(s) disponible(s) en stock</strong>
            </p>
            {% endif %}
        </div>

        <!-- RESTRUCTURATION : INVENTAIRE GROUPÉ PAR LIEU DE STOCKAGE -->
        {% if grouped_articles %}
            {% for group in grouped_articles %}
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden mb-6">
                <!-- En-tête du Lieu -->
                <div class="bg-forest text-white px-4 py-3 flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 border-b border-emerald-900">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="text-base text-emerald-300">📍</span>
                        <h2 class="text-sm font-bold tracking-wide uppercase">{{ group.location_name }}</h2>
                        <span class="text-[11px] bg-forest-light text-emerald-200 px-2 py-0.5 rounded-full font-semibold border border-emerald-800">
                            {{ group['items'] | length }} article(s)
                        </span>
                    </div>
                    <div class="text-xs font-semibold text-emerald-300">
                        Valeur Lieu : {{ "%.2f"|format(group.total_value) }} €
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse text-xs print-table">
                        <thead>
                            <tr class="bg-emerald-50/60 text-slate-700 border-b border-slate-200 uppercase font-semibold text-[10px] tracking-wider">
                                <th class="p-2.5 border-r border-slate-200 text-center">Photo</th>
                                <th class="p-2.5 border-r border-slate-200">Statut</th>
                                <th class="p-2.5 border-r border-slate-200">N° Article</th>
                                <th class="p-2.5 border-r border-slate-200">Désignation</th>
                                <th class="p-2.5 border-r border-slate-200">Fournisseur / Facture</th>
                                <th class="p-2.5 border-r border-slate-200">Équipement</th>
                                <th class="p-2.5 border-r border-slate-200 text-right">Prix Unit.</th>
                                <th class="p-2.5 border-r border-slate-200 text-center">Stock Mini</th>
                                <th class="p-2.5 border-r border-slate-200 text-center">Quantité</th>
                                <th class="p-2.5 text-right border-r border-slate-200">Valeur Totale</th>
                                <th class="p-2.5 text-center no-print">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-200">
                            {% for item in group['items'] %}
                            <tr class="{% if item.quantity < item.min_threshold %}bg-rose-50/80 hover:bg-rose-100/80{% else %}hover:bg-slate-50/60{% endif %} transition">
                                <td class="p-2 border-r border-slate-200">
                                    {% if item.image_filename %}
                                    <img
                                        src="{{ url_for('uploaded_file', filename=item.image_filename) }}"
                                        alt="Photo de {{ item.name }}"
                                        loading="lazy"
                                        class="w-14 h-14 rounded object-cover bg-slate-100 mx-auto"
                                    >
                                    {% else %}
                                    <span class="w-14 h-14 rounded bg-slate-100 text-slate-400 flex items-center justify-center mx-auto text-lg" aria-label="Aucune photo">📦</span>
                                    {% endif %}
                                </td>
                                <td class="p-2.5 font-bold border-r border-slate-200">
                                    {% if item.quantity == 0 %}
                                    <span class="px-2 py-0.5 rounded text-[9px] bg-slate-200 text-slate-800 font-bold uppercase">RUPTURE</span>
                                    {% elif item.quantity < item.min_threshold %}
                                    <span class="px-2 py-0.5 rounded text-[9px] bg-rose-200 text-rose-900 font-bold uppercase">RECOMMANDER</span>
                                    {% else %}
                                    <span class="px-2 py-0.5 rounded text-[9px] bg-emerald-100 text-emerald-900 font-semibold uppercase">OK</span>
                                    {% endif %}
                                </td>
                                <td class="p-2.5 font-mono text-slate-500 border-r border-slate-200">{{ item.reference or '-' }}</td>
                                <td class="p-2.5 font-semibold text-slate-900 border-r border-slate-200">
                                    {{ item.name }}
                                    {% if item.is_estimated_price %}
                                    <span class="text-[9px] text-amber-700 bg-amber-50 px-1 rounded ml-1 font-normal">(Est.)</span>
                                    {% endif %}
                                </td>
                                <td class="p-2.5 text-slate-600 border-r border-slate-200">
                                    <div class="font-medium text-slate-900">{{ item.supplier or '-' }}</div>
                                    <div class="text-[9px] text-slate-400">Fac: {{ item.invoice_number or '-' }} (Entrée: {{ item.entry_date or '-' }})</div>
                                </td>
                                <td class="p-2.5 text-slate-600 border-r border-slate-200">{{ item.eq_name or '-' }}</td>
                                <td class="p-2.5 text-right text-slate-700 border-r border-slate-200 font-mono">{{ "%.2f"|format(item.price) }} €</td>
                                <td class="p-2.5 text-center font-bold text-slate-600 border-r border-slate-200 bg-slate-50/50">{{ item.min_threshold }}</td>
                                <td class="p-2.5 text-center font-extrabold text-slate-900 border-r border-slate-200">{{ item.quantity }}</td>
                                <td class="p-2.5 text-right font-bold text-slate-900 font-mono border-r border-slate-200">{{ "%.2f"|format(item.quantity * item.price) }} €</td>
                                <td class="p-2.5 text-center no-print">
                                    <div class="flex items-center justify-center gap-1.5">
                                        <a href="/edit/{{ item.id }}" class="text-emerald-800 hover:underline font-semibold text-xs">✏️ Modif</a>
                                        <form action="/update/{{ item.id }}" method="POST" class="inline">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                            <input type="hidden" name="action" value="minus">
                                            <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">-</button>
                                        </form>
                                        <form action="/update/{{ item.id }}" method="POST" class="inline">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                            <input type="hidden" name="action" value="plus">
                                            <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">+</button>
                                        </form>
                                        <form action="/delete/{{ item.id }}" method="POST" onsubmit="return confirm('Supprimer cet article ?');" class="inline ml-1">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                            <button type="submit" class="text-rose-600 hover:underline text-xs">Suppr</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div class="bg-white rounded-lg border border-slate-200 p-8 text-center text-slate-400 text-xs shadow-sm">
                Aucun article ne correspond à votre recherche ou l'inventaire est vide.
            </div>
        {% endif %}
    </div>
    {% if show_rupture_popup %}
    <div id="rupture-popup" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4" role="dialog" aria-modal="true" aria-labelledby="rupture-popup-title">
        <section class="w-full max-w-lg rounded-xl bg-white shadow-2xl">
            <div class="flex items-start justify-between gap-4 border-b border-rose-100 bg-rose-50 p-5">
                <div>
                    <h2 id="rupture-popup-title" class="text-lg font-bold text-rose-900">⚠️ Articles en rupture</h2>
                    <p class="mt-1 text-sm text-rose-800">{{ rupture_count }} article(s) avec un stock à zéro.</p>
                </div>
                <button type="button" id="close-rupture-popup" aria-label="Fermer l'alerte" class="min-h-11 rounded px-3 text-xl text-slate-600 hover:bg-white">×</button>
            </div>
            <div class="max-h-[55vh] overflow-y-auto p-5">
                <ul class="divide-y divide-slate-100">
                    {% for item in rupture_articles %}
                    <li class="py-2 text-sm">
                        <span class="font-semibold text-slate-900">{{ item.name }}</span>
                        <span class="block text-xs text-slate-500">Réf. : {{ item.reference or 'Non renseignée' }} · {{ item.loc_name }}</span>
                    </li>
                    {% endfor %}
                </ul>
                {% if rupture_count > rupture_articles|length %}
                <p class="mt-3 text-xs text-slate-500">Et {{ rupture_count - rupture_articles|length }} autre(s) article(s).</p>
                {% endif %}
            </div>
            <div class="flex flex-col-reverse gap-2 border-t border-slate-100 p-5 sm:flex-row sm:justify-end">
                <button type="button" id="dismiss-rupture-popup" class="min-h-11 rounded border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700">Fermer</button>
                <a href="{{ url_for('stock_view', stock_status='out') }}" class="min-h-11 rounded bg-rose-800 px-4 py-3 text-center text-sm font-semibold text-white hover:bg-rose-900">Afficher les articles en rupture</a>
            </div>
        </section>
    </div>
    <script>
        (() => {
            const popup = document.getElementById("rupture-popup");
            const closeButtons = [
                document.getElementById("close-rupture-popup"),
                document.getElementById("dismiss-rupture-popup")
            ];
            const closePopup = () => {
                popup.remove();
            };
            closeButtons.forEach((button) => button.addEventListener("click", closePopup));
            popup.addEventListener("click", (event) => {
                if (event.target === popup) closePopup();
            });
            document.addEventListener("keydown", (event) => {
                if (event.key === "Escape" && document.getElementById("rupture-popup")) closePopup();
            });
            closeButtons[0].focus();
        })();
    </script>
    {% endif %}
"""
    + LAYOUT_FOOTER
)

# --- MOVEMENT REPORT TEMPLATE ---
MOVEMENTS_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="mx-auto max-w-6xl space-y-6">
        <section class="rounded-xl bg-forest p-5 text-white shadow-sm sm:p-6">
            <p class="text-xs font-semibold uppercase tracking-wider text-emerald-200">Historique des opérations</p>
            <h1 class="mt-1 text-2xl font-extrabold">Suivi des mouvements de stock</h1>
            <p class="mt-2 text-sm text-emerald-100">Filtrez les entrées et sorties par période et par article. Les montants utilisent le prix unitaire enregistré au moment du mouvement.</p>
        </section>

        <section class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5 no-print">
            <form method="GET" action="{{ url_for('movement_report') }}" class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5 lg:items-end">
                <label class="text-sm font-semibold text-slate-700">Du
                    <input type="date" name="date_from" value="{{ date_from }}" required class="mt-1 w-full rounded border border-slate-300 p-2">
                </label>
                <label class="text-sm font-semibold text-slate-700">Au
                    <input type="date" name="date_to" value="{{ date_to }}" required class="mt-1 w-full rounded border border-slate-300 p-2">
                </label>
                <label class="text-sm font-semibold text-slate-700">Article
                    <select name="article_id" class="mt-1 w-full rounded border border-slate-300 bg-white p-2">
                        <option value="">Tous les articles</option>
                        {% for item in articles %}
                        <option value="{{ item.id }}" {% if current_article_id == item.id %}selected{% endif %}>{{ item.name }}{% if item.reference %} — {{ item.reference }}{% endif %}</option>
                        {% endfor %}
                    </select>
                </label>
                <div class="flex gap-2 lg:col-span-2">
                    <button type="submit" class="min-h-11 flex-1 rounded bg-forest px-4 py-2 text-sm font-bold text-white hover:bg-forest-light">Afficher</button>
                    <a href="{{ url_for('movement_report') }}" class="flex min-h-11 items-center rounded bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-200">Réinitialiser</a>
                </div>
            </form>
        </section>

        <section class="rounded-xl border border-slate-200 bg-white shadow-sm">
            <div class="flex flex-col gap-2 border-b border-slate-200 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
                <div>
                    <h2 class="font-bold text-slate-900">Résultats</h2>
                    <p class="text-sm text-slate-600">{{ total_movement_count }} mouvement(s) du {{ date_from }} au {{ date_to }} · page {{ current_page }} / {{ total_pages }}</p>
                </div>
                <div class="text-sm font-bold text-slate-800">Valeur totale des mouvements : {{ "%.2f"|format(total_movement_value) }} €</div>
            </div>
            {% if movements %}
            <div class="overflow-x-auto">
                <table class="w-full min-w-[850px] text-left text-sm">
                    <thead class="bg-slate-50 text-xs uppercase text-slate-600">
                        <tr>
                            <th class="p-3">Date</th>
                            <th class="p-3">Mouvement</th>
                            <th class="p-3">Article</th>
                            <th class="p-3 text-right">Quantité</th>
                            <th class="p-3">Motif</th>
                            <th class="p-3 text-right">Prix unitaire</th>
                            <th class="p-3 text-right">Valeur</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-100">
                        {% for movement in movements %}
                        <tr class="hover:bg-slate-50">
                            <td class="whitespace-nowrap p-3">{{ movement.date.strftime('%d/%m/%Y %H:%M') if movement.date else '—' }}</td>
                            <td class="p-3"><span class="rounded px-2 py-1 text-xs font-bold {% if movement.type == 'ENTREE' %}bg-emerald-100 text-emerald-900{% else %}bg-amber-100 text-amber-900{% endif %}">{{ movement.type }}</span></td>
                            <td class="p-3 font-semibold">{{ movement.article_name or 'Article supprimé' }}{% if movement.reference %}<span class="block text-xs font-normal text-slate-500">{{ movement.reference }}</span>{% endif %}</td>
                            <td class="p-3 text-right font-semibold">{{ movement.quantity }}</td>
                            <td class="max-w-xs p-3">{{ movement.reason or '—' }}{% if movement.supplier %}<span class="block text-xs text-slate-500">Fournisseur : {{ movement.supplier }}</span>{% endif %}{% if movement.invoice_number %}<span class="block text-xs text-slate-500">Facture : {{ movement.invoice_number }}</span>{% endif %}</td>
                            <td class="whitespace-nowrap p-3 text-right">{% if movement.unit_price is not none %}{{ "%.2f"|format(movement.unit_price) }} €{% if movement.uses_current_price %}<span class="block text-xs font-normal text-slate-500">prix actuel (ancien mouvement)</span>{% endif %}{% else %}—{% endif %}</td>
                            <td class="whitespace-nowrap p-3 text-right font-semibold">{% if movement.movement_value is not none %}{{ "%.2f"|format(movement.movement_value) }} €{% else %}—{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <p class="p-8 text-center text-sm text-slate-500">Aucun mouvement sur cette période pour ce filtre.</p>
            {% endif %}
            {% if total_pages > 1 %}
            <nav class="flex items-center justify-between border-t border-slate-200 p-4" aria-label="Pagination des mouvements">
                {% if has_previous_page %}
                <a href="{{ url_for('movement_report', date_from=date_from, date_to=date_to, article_id=current_article_id, page=current_page - 1) }}" class="min-h-11 rounded border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50">← Précédent</a>
                {% else %}
                <span class="min-h-11 rounded border border-slate-200 px-4 py-2 text-sm text-slate-400">← Précédent</span>
                {% endif %}
                <span class="text-sm text-slate-600">Page {{ current_page }} / {{ total_pages }}</span>
                {% if has_next_page %}
                <a href="{{ url_for('movement_report', date_from=date_from, date_to=date_to, article_id=current_article_id, page=current_page + 1) }}" class="min-h-11 rounded border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50">Suivant →</a>
                {% else %}
                <span class="min-h-11 rounded border border-slate-200 px-4 py-2 text-sm text-slate-400">Suivant →</span>
                {% endif %}
            </nav>
            {% endif %}
        </section>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- MONTHLY STOCK CLOSING TEMPLATE ---
MONTHLY_CLOSE_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <style>
        .closing-table { min-width: 1050px; }
        @media print {
            @page { size: landscape; margin: 12mm; }
            .closing-table { min-width: 0 !important; font-size: 8pt !important; }
            .closing-table th, .closing-table td { padding: 4px !important; }
            .closing-table thead { display: table-header-group; }
            .closing-table tr { break-inside: avoid; }
            .closing-section { break-inside: avoid; }
            body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
    </style>
    <div class="mx-auto max-w-7xl space-y-5">
        <section class="rounded-xl bg-forest p-5 text-white shadow-sm sm:p-6">
            <div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div>
                    <p class="text-xs font-semibold uppercase tracking-wider text-emerald-200">Contrôle de gestion · Inventaire</p>
                    <h1 class="mt-1 text-2xl font-extrabold">État mensuel des stocks</h1>
                    <p class="mt-2 text-sm text-emerald-100">Période : {{ period_label }} · du {{ period_start_label }} au {{ period_end_label }}</p>
                    {% if current_month %}<p class="mt-2 inline-flex rounded bg-amber-300 px-2 py-1 text-xs font-bold text-amber-950">Période en cours · état provisoire</p>{% endif %}
                </div>
                <div class="no-print flex flex-wrap gap-2">
                    <form method="GET" action="{{ url_for('monthly_close') }}" class="flex items-center gap-2">
                        <label for="closing-month" class="sr-only">Mois à clôturer</label>
                        <input id="closing-month" type="month" name="month" value="{{ month_key }}" max="{{ current_month_key }}" required class="min-h-11 rounded border border-white/30 bg-white px-3 text-sm text-slate-900">
                        <button type="submit" class="min-h-11 rounded bg-emerald-500 px-4 py-2 text-sm font-bold text-white hover:bg-emerald-600">Afficher</button>
                    </form>
                    <button type="button" onclick="window.print()" class="min-h-11 rounded border border-white/40 px-4 py-2 text-sm font-bold text-white hover:bg-white/10">Imprimer / PDF</button>
                </div>
            </div>
            <p class="mt-4 rounded-lg border border-emerald-700 bg-emerald-950/40 p-3 text-xs leading-relaxed text-emerald-100">
                Méthode : CUMP mobile reconstitué à partir des mouvements enregistrés, sans arrondi intermédiaire.
                Les sorties sont valorisées au coût moyen pondéré avant sortie. Une histoire de stock ou de prix incomplète
                est signalée dans le détail ; les montants présentés ne remplacent pas une validation comptable.
            </p>
            <p class="mt-2 text-right text-[11px] text-emerald-200">Édité le {{ generated_at }}</p>
        </section>

        {% if unverified_count or unvalued_count or legacy_price_status_count or estimated_count or orphaned_movement_count %}
        <section class="rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950" role="alert">
            <h2 class="font-bold">Points de contrôle avant validation</h2>
            <ul class="mt-1 list-inside list-disc space-y-1">
                {% if unverified_count %}<li>{{ unverified_count }} article(s) ont un historique de quantité incomplet ou différent du stock actuel ; leurs soldes sont marqués « À vérifier ».</li>{% endif %}
                {% if unvalued_count %}<li>{{ unvalued_count }} article(s) en stock n’ont pas de coût d’entrée exploitable pour calculer leur CUMP.</li>{% endif %}
                {% if legacy_price_status_count %}<li>Le caractère estimatif de prix d’entrée anciens n’est pas historisé pour {{ legacy_price_status_count }} article(s) ; vérifiez les justificatifs d’achat.</li>{% endif %}
                {% if estimated_count %}<li>{{ estimated_count }} article(s) ont un coût d’entrée estimatif ou un statut de prix historique incomplet.</li>{% endif %}
                {% if orphaned_movement_count %}<li>{{ orphaned_movement_count }} mouvement(s) antérieur(s) à la clôture concernent des articles supprimés et ne peuvent pas être ventilés ; les synthèses sont incomplètes.</li>{% endif %}
            </ul>
        </section>
        {% endif %}

        <section class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p class="text-xs font-semibold uppercase text-slate-500">Stock d’ouverture · CUMP</p>
                <p class="mt-1 text-xl font-extrabold text-slate-900">{{ "%.2f"|format(opening_value) }} €</p>
                {% if opening_unvalued_count or unverified_count or orphaned_movement_count %}<p class="mt-1 text-xs text-amber-800">Partiel · {{ opening_unvalued_count }} non valorisé(s), {{ unverified_count }} à vérifier</p>{% endif %}
            </div>
            <div class="rounded-lg border border-emerald-200 bg-white p-4 shadow-sm">
                <p class="text-xs font-semibold uppercase text-slate-500">Entrées du mois</p>
                <p class="mt-1 text-xl font-extrabold text-emerald-900">{{ "%.2f"|format(entries_value) }} €</p>
                <p class="mt-1 text-xs text-slate-600">{{ entries_quantity }} unité(s){% if entries_unvalued_count or unverified_count or orphaned_movement_count %} · total partiel{% endif %}</p>
            </div>
            <div class="rounded-lg border border-amber-200 bg-white p-4 shadow-sm">
                <p class="text-xs font-semibold uppercase text-slate-500">Sorties du mois · CUMP</p>
                <p class="mt-1 text-xl font-extrabold text-amber-900">{{ "%.2f"|format(exits_value) }} €</p>
                <p class="mt-1 text-xs text-slate-600">{{ exits_quantity }} unité(s){% if exits_unvalued_count or unverified_count or orphaned_movement_count %} · total partiel{% endif %}</p>
            </div>
            <div class="rounded-lg border border-forest bg-white p-4 shadow-sm">
                <p class="text-xs font-semibold uppercase text-slate-500">Stock de clôture · CUMP</p>
                <p class="mt-1 text-xl font-extrabold text-forest">{{ "%.2f"|format(closing_value) }} €</p>
                <p class="mt-1 text-xs text-slate-600">{{ closing_quantity }} unité(s){% if unvalued_count or unverified_count or orphaned_movement_count %} · total partiel{% endif %}</p>
            </div>
        </section>

        <section class="closing-section overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div class="flex flex-col gap-1 border-b border-slate-200 p-4 sm:flex-row sm:items-end sm:justify-between">
                <div>
                    <h2 class="font-bold text-slate-900">Détail par article</h2>
                    <p class="text-xs text-slate-600">{{ monthly_close_rows|length }} article(s) · Soldes issus du journal jusqu’à la fin de période</p>
                </div>
                <p class="text-xs text-slate-500">Les lignes « Estimé » ou « À vérifier » nécessitent un contrôle manuel.</p>
            </div>
            <div class="overflow-x-auto">
                <table class="closing-table w-full border-collapse text-left text-xs">
                    <thead class="bg-slate-100 text-[10px] uppercase tracking-wide text-slate-600">
                        <tr>
                            <th class="p-2">Statut</th>
                            <th class="p-2">Référence</th>
                            <th class="p-2">Article</th>
                            <th class="p-2">Emplacement / équipement</th>
                            <th class="p-2 text-right">Ouverture Qté</th>
                            <th class="p-2 text-right">Entrées Qté</th>
                            <th class="p-2 text-right">Entrées €</th>
                            <th class="p-2 text-right">Sorties Qté</th>
                            <th class="p-2 text-right">Sorties €</th>
                            <th class="p-2 text-right">Clôture Qté</th>
                            <th class="p-2 text-right">CUMP clôture</th>
                            <th class="p-2 text-right">Valeur clôture</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-100">
                        {% for item in monthly_close_rows %}
                        <tr class="{% if item.status == 'À vérifier' %}bg-rose-50{% elif item.status != 'OK' %}bg-amber-50{% else %}hover:bg-slate-50{% endif %}">
                            <td class="whitespace-nowrap p-2 font-semibold {% if item.status == 'À vérifier' %}text-rose-800{% elif item.status != 'OK' %}text-amber-800{% else %}text-emerald-800{% endif %}">{{ item.status }}</td>
                            <td class="p-2 font-mono">{{ item.reference or '—' }}</td>
                            <td class="p-2 font-semibold text-slate-900">{{ item.name }}{% if item.issues %}<span class="mt-1 block whitespace-normal text-[10px] font-normal text-rose-800">{{ item.issues }}</span>{% endif %}</td>
                            <td class="p-2">{{ item.location_name }}{% if item.equipment_name %}<span class="block text-slate-500">{{ item.equipment_name }}</span>{% endif %}</td>
                            <td class="p-2 text-right">{{ item.opening_quantity if item.opening_quantity is not none else 'À vérifier' }}</td>
                            <td class="p-2 text-right">{{ item.entries_quantity }}</td>
                            <td class="whitespace-nowrap p-2 text-right">{% if item.entries_value is not none %}{{ "%.2f"|format(item.entries_value) }} €{% else %}—{% endif %}</td>
                            <td class="p-2 text-right">{{ item.exits_quantity }}</td>
                            <td class="whitespace-nowrap p-2 text-right">{% if item.exits_value is not none %}{{ "%.2f"|format(item.exits_value) }} €{% else %}—{% endif %}</td>
                            <td class="p-2 text-right font-bold">{{ item.closing_quantity if item.closing_quantity is not none else 'À vérifier' }}</td>
                            <td class="whitespace-nowrap p-2 text-right">{% if item.closing_cump is not none %}{{ "%.2f"|format(item.closing_cump) }} €{% else %}—{% endif %}</td>
                            <td class="whitespace-nowrap p-2 text-right font-bold">{% if item.closing_value is not none %}{{ "%.2f"|format(item.closing_value) }} €{% else %}—{% endif %}</td>
                        </tr>
                        {% else %}
                        <tr><td colspan="12" class="p-8 text-center text-slate-500">Aucun article à présenter.</td></tr>
                        {% endfor %}
                    </tbody>
                    <tfoot class="border-t-2 border-slate-300 bg-slate-50 font-bold text-slate-900">
                        <tr>
                            <td colspan="4" class="p-2">Totaux des lignes vérifiées / valorisables</td>
                            <td class="p-2 text-right">{{ opening_quantity }}</td>
                            <td class="p-2 text-right">{{ entries_quantity }}</td>
                            <td class="p-2 text-right">{{ "%.2f"|format(entries_value) }} €</td>
                            <td class="p-2 text-right">{{ exits_quantity }}</td>
                            <td class="p-2 text-right">{{ "%.2f"|format(exits_value) }} €</td>
                            <td class="p-2 text-right">{{ closing_quantity }}</td>
                            <td class="p-2"></td>
                            <td class="p-2 text-right">{{ "%.2f"|format(closing_value) }} €</td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        </section>
        <p class="text-[11px] leading-relaxed text-slate-500">
            Contrôle : les soldes sont reconstitués à partir des mouvements, en supposant un stock initial nul avant le premier mouvement enregistré.
            Le statut « À vérifier » signale notamment un mouvement de sortie sans solde antérieur documenté ou un écart avec le stock actuel.
            Les anciens prix estimatifs ne sont pas toujours identifiables. Les prix proviennent d’un type numérique flottant et les montants sont arrondis à deux décimales à l’affichage ; vérifiez les justificatifs et la règle de valorisation comptable avant validation.
        </p>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- EDIT ARTICLE TEMPLATE ---
EDIT_ARTICLE_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-2xl mx-auto space-y-6">
        {% if article_created %}
        <p class="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm font-semibold text-emerald-900 no-print" role="status">Article créé. Imprimez son QR code : le scanner avec l’appareil photo du téléphone ouvre directement le choix Entrée ou Sortie de stock. Une connexion sera demandée si nécessaire.</p>
        {% endif %}
        <div class="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-4 no-print">
            <div class="flex justify-between items-center pb-3 border-b border-slate-200">
                <h1 class="text-base font-bold text-slate-900">✏️ Modifier l'Article</h1>
                <a href="/stock" class="text-xs text-emerald-800 hover:underline font-semibold">← Retour au tableau</a>
            </div>

            <form action="/edit/{{ article.id }}" method="POST" enctype="multipart/form-data" class="space-y-4">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div class="md:col-span-2">
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Désignation / Nom *</label>
                        <input type="text" name="name" value="{{ article.name }}" required class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                        <input type="text" name="reference" value="{{ article.reference or '' }}" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité *</label>
                        <input type="number" name="quantity" value="{{ article.quantity }}" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Stock Mini *</label>
                        <input type="number" name="min_threshold" value="{{ article.min_threshold }}" min="0" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold text-rose-600">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Prix Unitaire (€)</label>
                        <input type="number" step="0.01" name="price" value="{{ article.price }}" required class="w-full text-xs p-2.5 border border-slate-300 rounded">
                    </div>
                    <div class="flex items-end pb-2">
                        <label class="flex items-center gap-2 text-xs text-slate-600 cursor-pointer">
                            <input type="checkbox" name="is_estimated_price" value="1" {% if article.is_estimated_price %}checked{% endif %} class="rounded border-slate-300 text-emerald-800">
                            <span>Prix estimé</span>
                        </label>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4 bg-emerald-50/40 p-3 rounded border border-emerald-100">
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Fournisseur</label>
                        <input type="text" name="supplier" value="{{ article.supplier or '' }}" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">N° de facture</label>
                        <input type="text" name="invoice_number" value="{{ article.invoice_number or '' }}" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Date d'entrée</label>
                        <input type="date" name="entry_date" value="{{ article.entry_date or '' }}" class="w-full text-xs p-2 border border-slate-300 rounded bg-white font-medium">
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Emplacement</label>
                        <select name="location_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                            <option value="">-- Aucun --</option>
                            {% for loc in locations %}
                            <option value="{{ loc.id }}" {% if article.location_id == loc.id %}selected{% endif %}>{{ loc.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Équipement</label>
                        <select name="equipment_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
                            <option value="">-- Aucun --</option>
                            {% for eq in equipment %}
                            <option value="{{ eq.id }}" {% if article.equipment_id == eq.id %}selected{% endif %}>{{ eq.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </div>

                <div>
                    <label class="block text-xs font-semibold text-slate-600 mb-1">Remplacer la photo (Optionnel)</label>
                    <input type="file" name="photo" accept="image/*" class="w-full text-xs text-slate-500">
                </div>

                <div class="flex gap-3 pt-2">
                    <button type="submit" class="flex-1 bg-forest hover:bg-forest-light text-white font-semibold py-2.5 rounded text-xs transition">Mettre à jour l'article</button>
                    <a href="/stock" class="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded text-center">Annuler</a>
                </div>
            </form>
        </div>
        <style>
            @page { size: 85mm 55mm; margin: 0; }
        </style>
        <section class="article-qr-card rounded-xl border border-slate-200 bg-white p-5 text-center shadow-sm">
            <div class="article-qr-code mx-auto mt-4 w-fit rounded-lg border border-slate-200 bg-white p-3">
                <img src="{{ qr_code_data }}" alt="QR code de l’article {{ article.name }}" class="h-56 w-56">
            </div>
            <div class="article-qr-details">
                <h2 class="text-lg font-bold text-slate-900">{{ article.name }}</h2>
                <p class="article-reference text-sm text-slate-600">Réf. : {{ article.reference or '—' }}</p>
                <p class="qr-scan-hint mt-1 text-xs text-slate-500">Scanner pour entrée ou sortie</p>
            </div>
            <div class="mt-4 flex flex-col justify-center gap-2 sm:flex-row no-print">
                <button type="button" onclick="window.print()" class="min-h-11 rounded-lg bg-emerald-800 px-4 py-2 text-sm font-bold text-white hover:bg-emerald-900">Imprimer le QR code</button>
                <a href="{{ qr_code_data }}" download="qr-article-{{ article.id }}.png" class="flex min-h-11 items-center justify-center rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50">Télécharger l’image</a>
            </div>
        </section>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- 3. PAGE DE RÉGLAGES ---
SETTINGS_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-white rounded-lg border border-slate-200 p-4 shadow-sm">
            <h1 class="text-base font-bold text-slate-900">Réglages & Configuration</h1>
            <p class="text-xs text-slate-500">Gérez et modifiez les emplacements physiques et les équipements associés</p>
        </div>
        {% for category, message in get_flashed_messages(with_categories=true) %}
        <p role="status" class="rounded p-3 text-sm {% if category == 'error' %}bg-rose-50 text-rose-800{% else %}bg-emerald-50 text-emerald-800{% endif %}">{{ message }}</p>
        {% endfor %}

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- Emplacements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    📍 Emplacements de Stockage
                </h2>
                <form action="/add_location" method="POST" class="flex gap-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="text" name="name" required placeholder="Nouveau lieu..." class="flex-grow text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    <button type="submit" class="bg-forest hover:bg-forest-light text-white px-3 py-2 rounded text-xs font-semibold transition">Ajouter</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for loc in locations %}
                    <div class="py-2.5 flex justify-between items-center">
                        <form action="/edit_location/{{ loc.id }}" method="POST" class="flex items-center gap-2 flex-grow mr-2">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <input type="text" name="name" value="{{ loc.name }}" required class="text-xs p-1 border border-transparent hover:border-slate-300 focus:border-emerald-700 rounded flex-grow font-semibold text-slate-700">
                            <button type="submit" class="text-emerald-800 hover:underline text-[11px] font-medium">Sauvegarder</button>
                        </form>
                        <form action="/delete_location/{{ loc.id }}" method="POST" onsubmit="return confirm('Supprimer ce lieu ?');">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="text-rose-600 hover:underline text-[11px]">Supprimer</button>
                        </form>
                    </div>
                    {% else %}
                    <p class="text-slate-400 text-xs italic">Aucun lieu configuré.</p>
                    {% endfor %}
                </div>
            </div>

            <!-- Équipements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    ⚙️ Équipements & Machines
                </h2>
                <form action="/add_equipment" method="POST" class="space-y-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="text" name="name" required placeholder="Nom de l'équipement..." class="w-full text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    <select name="location_id" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                        <option value="">-- Rattacher à un emplacement --</option>
                        {% for loc in locations %}
                        <option value="{{ loc.id }}">{{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="w-full bg-forest hover:bg-forest-light text-white py-2 rounded text-xs font-semibold transition">Ajouter l'Équipement</button>
                </form>

                <div class="space-y-1">
                    <label for="equipment-search" class="block text-xs font-semibold text-slate-700">Rechercher un équipement</label>
                    <input
                        id="equipment-search"
                        type="search"
                        placeholder="Nom de machine ou emplacement…"
                        aria-label="Rechercher un équipement ou une machine"
                        aria-controls="equipment-list"
                        class="w-full text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700"
                    >
                    <p id="equipment-search-count" class="text-[11px] text-slate-500" aria-live="polite">{{ equipment|length }} équipement(s)</p>
                </div>

                <div id="equipment-list" class="divide-y divide-slate-100 text-xs pt-2">
                    {% for eq in equipment %}
                    <div class="equipment-search-item py-3 space-y-1" data-search="{{ eq.name }} {{ eq.loc_name or '' }}">
                        <form action="/edit_equipment/{{ eq.id }}" method="POST" class="space-y-1.5">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <div class="flex gap-2">
                                <input type="text" name="name" value="{{ eq.name }}" required class="text-xs p-1 border border-slate-200 rounded flex-grow font-semibold text-slate-800 focus:border-emerald-700">
                                <button type="submit" class="text-emerald-800 hover:underline text-[11px] font-medium">Sauvegarder</button>
                            </div>
                            <div class="flex justify-between items-center">
                                <select name="location_id" class="text-[11px] p-1 border border-slate-200 rounded bg-white text-slate-600">
                                    <option value="">-- Aucun lieu --</option>
                                    {% for loc in locations %}
                                    <option value="{{ loc.id }}" {% if eq.location_id == loc.id %}selected{% endif %}>📍 {{ loc.name }}</option>
                                    {% endfor %}
                                </select>
                                <button type="submit" form="del_eq_{{ eq.id }}" class="text-rose-600 hover:underline text-[11px]">Supprimer</button>
                            </div>
                        </form>
                        <form id="del_eq_{{ eq.id }}" action="/delete_equipment/{{ eq.id }}" method="POST" onsubmit="return confirm('Supprimer cet équipement ?');"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"></form>
                    </div>
                    {% else %}
                    <p class="text-slate-400 text-xs italic">Aucun équipement configuré.</p>
                    {% endfor %}
                </div>
                <p id="equipment-search-empty" class="hidden text-slate-400 text-xs italic" role="status">Aucun équipement ne correspond à cette recherche.</p>
            </div>
        </div>
        {% if current_user.role == 'admin' %}
        <section class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
            <div>
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider">Gestion des utilisateurs</h2>
                <p class="text-xs text-slate-500 mt-1">Les nouveaux comptes n'ont pas accès à la gestion des utilisateurs.</p>
            </div>
            <form action="{{ url_for('add_user') }}" method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-3">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input name="username" required minlength="3" maxlength="64" autocomplete="username" placeholder="Identifiant ou e-mail" title="3 à 64 caractères ; lettres, chiffres, point, tiret, souligné, @ ou +" class="text-xs p-2 border border-slate-300 rounded">
                <input type="password" name="password" required minlength="12" autocomplete="new-password" placeholder="Mot de passe (12 caractères min.)" class="text-xs p-2 border border-slate-300 rounded">
                <select name="role" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="user">Utilisateur</option>
                    <option value="admin">Administrateur</option>
                </select>
                <button type="submit" class="bg-forest hover:bg-forest-light text-white rounded text-xs font-semibold">Créer le compte</button>
            </form>
            <div class="divide-y divide-slate-100">
                {% for account in users %}
                <div class="py-3 flex flex-col gap-3">
                    <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <span class="font-semibold text-slate-800">{{ account.username }}</span>
                        <span class="text-slate-500">{{ 'Administrateur' if account.role == 'admin' else 'Utilisateur' }} · {{ 'Actif' if account.active else 'Désactivé' }}</span>
                        {% if account.id != current_user.id %}
                        <form action="{{ url_for('toggle_user', user_id=account.id) }}" method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="text-xs font-medium {% if account.active %}text-rose-700{% else %}text-emerald-800{% endif %}">{{ 'Désactiver' if account.active else 'Réactiver' }}</button>
                        </form>
                        {% else %}
                        <span class="text-slate-400">Votre compte</span>
                        {% endif %}
                    </div>
                    <form action="{{ url_for('reset_user_password', user_id=account.id) }}" method="POST" class="flex flex-wrap gap-2">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="password" name="password" required minlength="12" autocomplete="new-password" placeholder="Nouveau mot de passe (12 caractères min.)" class="flex-grow text-xs p-2 border border-slate-300 rounded">
                        <button type="submit" class="text-xs px-3 py-2 rounded bg-slate-100 hover:bg-slate-200">Réinitialiser le mot de passe</button>
                    </form>
                </div>
                {% else %}
                <p class="text-slate-400 text-xs italic py-3">Aucun utilisateur.</p>
                {% endfor %}
            </div>
        </section>
        {% endif %}
    </div>
    <script>
        const equipmentSearch = document.getElementById("equipment-search");
        if (equipmentSearch) {
            const equipmentItems = Array.from(document.querySelectorAll(".equipment-search-item"));
            const emptyMessage = document.getElementById("equipment-search-empty");
            const resultCount = document.getElementById("equipment-search-count");
            const normalize = (value) => value.normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLocaleLowerCase();
            equipmentSearch.addEventListener("input", () => {
                const query = normalize(equipmentSearch.value.trim());
                let visibleCount = 0;
                equipmentItems.forEach((item) => {
                    const matches = normalize(item.dataset.search || "").includes(query);
                    item.hidden = !matches;
                    if (matches) visibleCount += 1;
                });
                emptyMessage.classList.toggle("hidden", visibleCount > 0 || query === "");
                resultCount.textContent = `${visibleCount} équipement(s)`;
            });
        }
    </script>
"""
    + LAYOUT_FOOTER
)


# --- ROUTES FLASK ---


def calculate_total_stock_value():
  db = get_db()
  cur = db.cursor()
  cur.execute(
      """
          SELECT COALESCE(SUM(quantity * COALESCE(price, 0)), 0) AS total
          FROM articles
      """
  )
  total = cur.fetchone()["total"]
  cur.close()
  return total


def build_monthly_close_rows(articles, movements, period_start, period_end):
  states = {}
  for article in articles:
    states[article["id"]] = {
        "article": article,
        "quantity": 0,
        "value": Decimal("0"),
        "quantity_known": True,
        "value_known": True,
        "estimated": False,
        "estimate_status_unknown": False,
        "legacy_price_status_seen": False,
        "has_movement": False,
        "opening": None,
        "closing": None,
        "entries_quantity": 0,
        "entries_value": Decimal("0"),
        "entries_value_known": True,
        "entries_estimated": False,
        "exits_quantity": 0,
        "exits_value": Decimal("0"),
        "exits_value_known": True,
        "exits_estimated": False,
        "issues": [],
    }

  def add_issue(state, message):
    if message not in state["issues"]:
      state["issues"].append(message)

  def snapshot(state):
    quantity = state["quantity"] if state["quantity_known"] else None
    value = None
    if quantity is not None:
      if not quantity:
        value = Decimal("0")
      elif state["value_known"]:
        value = state["value"]
    return {
        "quantity": quantity,
        "value": value,
        "estimated": state["estimated"],
        "estimate_status_unknown": state["estimate_status_unknown"],
    }

  for movement in movements:
    state = states.get(movement["article_id"])
    if state is None:
      continue
    movement_date = movement["date"]
    if movement_date is None:
      state["quantity_known"] = False
      state["value_known"] = False
      add_issue(state, "Date de mouvement manquante dans l'historique.")
      continue
    if isinstance(movement_date, datetime.date) and not isinstance(
        movement_date, datetime.datetime
    ):
      movement_date = datetime.datetime.combine(
          movement_date, datetime.time.min
      )

    if state["opening"] is None and movement_date >= period_start:
      state["opening"] = snapshot(state)
    if state["closing"] is None and movement_date >= period_end:
      if state["opening"] is None:
        state["opening"] = snapshot(state)
      state["closing"] = snapshot(state)

    in_period = period_start <= movement_date < period_end
    movement_type = movement["type"]
    quantity = movement["quantity"]
    if not isinstance(quantity, int) or quantity < 0:
      state["quantity_known"] = False
      state["value_known"] = False
      if movement_date < period_end:
        add_issue(state, "Quantité de mouvement invalide.")
      state["has_movement"] = True
      continue

    if movement_type not in {"ENTREE", "SORTIE"}:
      state["quantity_known"] = False
      state["value_known"] = False
      if movement_date < period_end:
        add_issue(state, "Type de mouvement non reconnu.")
      state["has_movement"] = True
      continue

    if (
        movement_type == "SORTIE"
        and quantity > 0
        and not state["has_movement"]
    ):
      state["quantity_known"] = False
      state["value_known"] = False
      if movement_date < period_end:
        add_issue(state, "Première opération = sortie ; le stock initial n'est pas documenté.")

    if movement_type == "ENTREE":
      price = None
      try:
        price = Decimal(str(movement["unit_price"]))
      except (InvalidOperation, TypeError, ValueError):
        pass
      if price is not None and (not price.is_finite() or price < 0):
        price = None

      if in_period:
        state["entries_quantity"] += quantity
        if quantity and price is None:
          state["entries_value_known"] = False
        elif price is not None:
          state["entries_value"] += quantity * price

      if quantity and price is None:
        state["value_known"] = False
        if movement_date < period_end:
          add_issue(state, "Prix d'entrée absent ou invalide dans l'historique.")
      elif quantity and state["value_known"]:
        state["value"] += quantity * price

      if quantity:
        estimate_status = movement.get("unit_price_estimated")
        if estimate_status is True:
          state["estimated"] = True
          if in_period:
            state["entries_estimated"] = True
        elif estimate_status is None:
          state["estimate_status_unknown"] = True
          if movement_date < period_end:
            state["legacy_price_status_seen"] = True
          if movement_date < period_end:
            add_issue(
                state,
                "Caractère estimatif d'un prix d'entrée ancien non historisé.",
            )
          if in_period:
            state["entries_estimated"] = True
    elif quantity:
      previous_quantity = state["quantity"]
      if in_period:
        state["exits_quantity"] += quantity
        if (
            previous_quantity < quantity
            or not state["quantity_known"]
            or not state["value_known"]
        ):
          state["exits_value_known"] = False
        elif previous_quantity:
          state["exits_value"] += (
              state["value"] * quantity / previous_quantity
          )
        if state["estimated"] or state["estimate_status_unknown"]:
          state["exits_estimated"] = True

      if quantity > previous_quantity or previous_quantity <= 0:
        state["quantity_known"] = False
        state["value_known"] = False
        if movement_date < period_end:
          add_issue(state, "Sortie supérieure au solde reconstitué.")
      elif quantity == previous_quantity:
        state["value"] = Decimal("0")
        state["value_known"] = True
        state["estimated"] = False
        state["estimate_status_unknown"] = False
      elif state["value_known"]:
        state["value"] -= state["value"] * quantity / previous_quantity

    state["quantity"] += quantity if movement_type == "ENTREE" else -quantity
    if state["quantity"] < 0:
      state["quantity_known"] = False
      state["value_known"] = False
      if movement_date < period_end:
        add_issue(state, "Solde négatif dans l'historique.")
    state["has_movement"] = True

  rows = []
  for article_id, state in states.items():
    if state["opening"] is None:
      state["opening"] = snapshot(state)
    if state["closing"] is None:
      state["closing"] = snapshot(state)

    if state["quantity"] != state["article"]["current_quantity"]:
      state["opening"]["quantity"] = None
      state["opening"]["value"] = None
      state["closing"]["quantity"] = None
      state["closing"]["value"] = None
      add_issue(state, "Le solde du journal ne correspond pas au stock actuel.")

    opening = state["opening"]
    closing = state["closing"]
    verified = opening["quantity"] is not None and closing["quantity"] is not None
    if not verified:
      status = "À vérifier"
    elif closing["quantity"] and closing["value"] is None:
      status = "Non valorisable"
    elif (
        closing["estimated"]
        or state["entries_estimated"]
        or state["exits_estimated"]
    ):
      status = "Estimé"
    elif closing["estimate_status_unknown"]:
      status = "Prix historique à contrôler"
    else:
      status = "OK"

    closing_cump = None
    if closing["quantity"] is not None and closing["value"] is not None:
      closing_cump = (
          closing["value"] / closing["quantity"]
          if closing["quantity"]
          else Decimal("0")
      )

    location_name = article.get("loc_name") or "Non assigné"
    rows.append(
        {
            "id": article_id,
            "reference": article.get("reference"),
            "name": article["name"],
            "location_name": location_name,
            "equipment_name": article.get("eq_name"),
            "opening_quantity": opening["quantity"],
            "opening_value": opening["value"],
            "entries_quantity": state["entries_quantity"],
            "entries_value": (
                state["entries_value"]
                if state["entries_value_known"]
                else None
            ),
            "entries_estimated": state["entries_estimated"],
            "exits_quantity": state["exits_quantity"],
            "exits_value": (
                state["exits_value"] if state["exits_value_known"] else None
            ),
            "exits_estimated": state["exits_estimated"],
            "closing_quantity": closing["quantity"],
            "closing_cump": closing_cump,
            "closing_value": closing["value"],
            "closing_estimated": closing["estimated"],
            "closing_estimate_status_unknown": closing[
                "estimate_status_unknown"
            ],
            "contains_estimated_cost": (
                closing["estimated"]
                or state["entries_estimated"]
                or state["exits_estimated"]
            ),
            "quantity_verified": verified,
            "status": status,
            "issues": " ".join(state["issues"]),
            "has_legacy_price_status_unknown": state[
                "legacy_price_status_seen"
            ],
        }
    )

  rows.sort(key=lambda row: (row["location_name"].casefold(), row["name"].casefold()))
  totals = {
      "opening_quantity": 0,
      "opening_value": Decimal("0"),
      "opening_unvalued_count": 0,
      "entries_quantity": 0,
      "entries_value": Decimal("0"),
      "entries_unvalued_count": 0,
      "exits_quantity": 0,
      "exits_value": Decimal("0"),
      "exits_unvalued_count": 0,
      "closing_quantity": 0,
      "closing_value": Decimal("0"),
      "unverified_count": 0,
      "unvalued_count": 0,
      "legacy_price_status_count": 0,
      "estimated_count": 0,
  }
  for row in rows:
    if not row["quantity_verified"]:
      totals["unverified_count"] += 1
      continue

    totals["opening_quantity"] += row["opening_quantity"]
    totals["entries_quantity"] += row["entries_quantity"]
    totals["exits_quantity"] += row["exits_quantity"]
    totals["closing_quantity"] += row["closing_quantity"]

    if row["opening_value"] is not None:
      totals["opening_value"] += row["opening_value"]
    elif row["opening_quantity"]:
      totals["opening_unvalued_count"] += 1

    if row["entries_value"] is not None:
      totals["entries_value"] += row["entries_value"]
    elif row["entries_quantity"]:
      totals["entries_unvalued_count"] += 1

    if row["exits_value"] is not None:
      totals["exits_value"] += row["exits_value"]
    elif row["exits_quantity"]:
      totals["exits_unvalued_count"] += 1

    if row["closing_value"] is not None:
      totals["closing_value"] += row["closing_value"]
    elif row["closing_quantity"]:
      totals["unvalued_count"] += 1

    if row["has_legacy_price_status_unknown"]:
      totals["legacy_price_status_count"] += 1
    if row["contains_estimated_cost"]:
      totals["estimated_count"] += 1

  return rows, totals


@app.route("/")
def home():
  return redirect(url_for("stock_view"))


@app.route("/entry")
def entry_form():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()
  cur.execute(
      "SELECT a.*, l.name as loc_name FROM articles a LEFT JOIN locations l ON"
      " a.location_id = l.id ORDER BY a.name"
  )
  articles = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()
  today_str = datetime.date.today().strftime("%Y-%m-%d")
  preselected_article_id = optional_integer(
      request.args.get("article_id"), "article_id"
  )
  selected_article = next(
      (
          item
          for item in articles
          if item["id"] == preselected_article_id
      ),
      None,
  )
  mode = request.args.get("mode", "")
  if mode not in {"", "choose", "entry", "exit"}:
    abort(400, description="Mode de mouvement invalide.")
  return render_template_string(
      ENTRY_TEMPLATE,
      active_page="entry",
      locations=locations,
      equipment=equipment,
      articles=articles,
      total_stock_value=total_val,
      today_date=today_str,
      preselected_article_id=preselected_article_id,
      preselected_article_found=any(
          item["id"] == preselected_article_id for item in articles
      ),
      selected_article=selected_article,
      start_exit_mode=mode == "exit",
      start_entry_mode=mode == "entry",
      start_choice_mode=mode == "choose",
  )


@app.route("/stock")
def stock_view():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()

  search_query = request.args.get("search", "").strip()
  loc_filter = optional_integer(request.args.get("loc_filter"), "loc_filter")
  eq_filter = optional_integer(request.args.get("eq_filter"), "eq_filter")
  stock_status = request.args.get("stock_status", "")
  if stock_status not in {"", "out"}:
    abort(400, description="Filtre de disponibilité invalide.")

  query = """
        SELECT a.*, COALESCE(l.name, 'Non assigné') as loc_name, e.name as eq_name 
        FROM articles a
        LEFT JOIN locations l ON a.location_id = l.id
        LEFT JOIN equipment e ON a.equipment_id = e.id
        WHERE 1=1
    """
  params = []

  if search_query:
    search_terms = search_query.split()
    for term in search_terms:
      escaped_term = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
      query += " AND (a.name ILIKE %s OR COALESCE(a.reference, '') ILIKE %s)"
      params.extend([f"%{escaped_term}%", f"%{escaped_term}%"])
  if loc_filter:
    query += " AND a.location_id = %s"
    params.append(loc_filter)
  if eq_filter:
    query += " AND a.equipment_id = %s"
    params.append(eq_filter)
  if stock_status == "out":
    query += " AND a.quantity = 0"

  query += " ORDER BY loc_name ASC, a.name ASC"
  cur.execute(query, params)
  articles = cur.fetchall()
  cur.close()

  show_rupture_popup = False
  rupture_articles = []
  rupture_count = 0
  if not session.get("_rupture_popup_seen"):
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS count FROM articles WHERE quantity = 0")
    rupture_count = cur.fetchone()["count"]
    if rupture_count:
      cur.execute("""
          SELECT a.name, a.reference, COALESCE(l.name, 'Non assigné') AS loc_name
          FROM articles a
          LEFT JOIN locations l ON a.location_id = l.id
          WHERE a.quantity = 0
          ORDER BY a.name ASC
          LIMIT 50
      """)
      rupture_articles = cur.fetchall()
      show_rupture_popup = True
    cur.close()
    session["_rupture_popup_seen"] = True

  total_stock_value = calculate_total_stock_value()
  matched_article_count = len(articles)
  in_stock_count = sum(1 for item in articles if item["quantity"] > 0)

  # Groupement dynamique strict par lieu de stockage sous forme de listes de dictionnaires
  grouped_dict = {}
  for item in articles:
    loc_name = item["loc_name"]
    if loc_name not in grouped_dict:
      grouped_dict[loc_name] = {"items": [], "total_value": 0.0}
    grouped_dict[loc_name]["items"].append(item)
    grouped_dict[loc_name]["total_value"] += item["quantity"] * (
        item["price"] or 0.0
    )

  grouped_articles = [
      {
          "location_name": loc_name,
          "items": list(data["items"]),
          "total_value": data["total_value"],
      }
      for loc_name, data in grouped_dict.items()
  ]

  return render_template_string(
      STOCK_TEMPLATE,
      active_page="stock",
      locations=locations,
      equipment=equipment,
      grouped_articles=grouped_articles,
      search_query=search_query,
      matched_article_count=matched_article_count,
      in_stock_count=in_stock_count,
      current_stock_status=stock_status,
      current_loc=loc_filter,
      current_eq=eq_filter,
      total_stock_value=total_stock_value,
      show_rupture_popup=show_rupture_popup,
      rupture_articles=rupture_articles,
      rupture_count=rupture_count,
  )


@app.route("/movements")
def movement_report():
  page_size = 50
  today = datetime.date.today()
  default_from = today.replace(day=1)
  date_from_text = request.args.get("date_from", default_from.isoformat())
  date_to_text = request.args.get("date_to", today.isoformat())
  try:
    date_from = datetime.date.fromisoformat(date_from_text)
    date_to = datetime.date.fromisoformat(date_to_text)
  except ValueError:
    abort(400, description="La période demandée est invalide.")
  if date_from > date_to:
    abort(400, description="La date de début doit précéder ou égaler la date de fin.")
  current_article_id = optional_integer(
      request.args.get("article_id"), "article_id"
  )
  requested_page = optional_integer(request.args.get("page"), "page") or 1

  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT id, name, reference FROM articles ORDER BY name")
  articles = cur.fetchall()
  where_clause = "m.date >= %s AND m.date < %s + INTERVAL '1 day'"
  params = [date_from, date_to]
  if current_article_id:
    where_clause += " AND m.article_id = %s"
    params.append(current_article_id)
  cur.execute(
      """
          SELECT COUNT(*) AS total_count,
                 COALESCE(
                     SUM(
                         m.quantity
                         * CASE WHEN m.unit_price IS NULL THEN a.price ELSE m.unit_price END
                     ),
                     0
                 ) AS total_value
          FROM movements m
          LEFT JOIN articles a ON a.id = m.article_id
          WHERE
      """ + where_clause,
      params,
  )
  movement_summary = cur.fetchone()
  total_movement_count = movement_summary["total_count"]
  total_pages = max(1, (total_movement_count + page_size - 1) // page_size)
  current_page = min(requested_page, total_pages)

  query = """
      SELECT m.id, m.type, m.quantity, m.reason, m.date, m.supplier,
             m.invoice_number, a.name AS article_name, a.reference,
             m.unit_price AS recorded_unit_price,
             m.unit_price IS NULL AS uses_current_price,
             CASE WHEN m.unit_price IS NULL THEN a.price ELSE m.unit_price END
                 AS unit_price
      FROM movements m
      LEFT JOIN articles a ON a.id = m.article_id
      WHERE
  """ + where_clause
  query += " ORDER BY m.date DESC, m.id DESC LIMIT %s OFFSET %s"
  page_params = [*params, page_size, (current_page - 1) * page_size]
  cur.execute(query, page_params)
  movements = cur.fetchall()
  cur.close()

  total_movement_value = movement_summary["total_value"] or 0.0
  for movement in movements:
    unit_price = movement["unit_price"]
    movement["movement_value"] = (
        movement["quantity"] * unit_price if unit_price is not None else None
    )

  return render_template_string(
      MOVEMENTS_TEMPLATE,
      active_page="movements",
      articles=articles,
      movements=movements,
      date_from=date_from.isoformat(),
      date_to=date_to.isoformat(),
      current_article_id=current_article_id,
      total_movement_value=total_movement_value,
      total_movement_count=total_movement_count,
      current_page=current_page,
      total_pages=total_pages,
      has_previous_page=current_page > 1,
      has_next_page=current_page < total_pages,
      total_stock_value=calculate_total_stock_value(),
  )


@app.route("/monthly-close")
def monthly_close():
  today = datetime.date.today()
  current_month_start = today.replace(day=1)
  current_month_key = current_month_start.strftime("%Y-%m")
  previous_month = current_month_start - datetime.timedelta(days=1)
  month_key = request.args.get(
      "month", previous_month.replace(day=1).strftime("%Y-%m")
  )
  if not re.fullmatch(r"\d{4}-\d{2}", month_key):
    abort(400, description="Le mois demandé est invalide.")
  try:
    month_start_date = datetime.date.fromisoformat(f"{month_key}-01")
  except ValueError:
    abort(400, description="Le mois demandé est invalide.")
  if month_start_date > current_month_start:
    abort(400, description="La clôture ne peut pas porter sur un mois futur.")

  if month_start_date.month == 12:
    next_month_date = datetime.date(month_start_date.year + 1, 1, 1)
  else:
    next_month_date = datetime.date(
        month_start_date.year, month_start_date.month + 1, 1
    )
  period_start = datetime.datetime.combine(
      month_start_date, datetime.time.min
  )
  period_end = datetime.datetime.combine(next_month_date, datetime.time.min)
  month_names = (
      "janvier", "février", "mars", "avril", "mai", "juin",
      "juillet", "août", "septembre", "octobre", "novembre", "décembre",
  )
  period_label = f"{month_names[month_start_date.month - 1]} {month_start_date.year}"
  period_end_date = next_month_date - datetime.timedelta(days=1)
  db = get_db()
  cur = db.cursor()
  cur.execute("""
      SELECT a.id, a.name, a.reference, a.quantity AS current_quantity,
             l.name AS loc_name, e.name AS eq_name
      FROM articles a
      LEFT JOIN locations l ON l.id = a.location_id
      LEFT JOIN equipment e ON e.id = a.equipment_id
      ORDER BY COALESCE(l.name, 'Non assigné'), a.name
  """)
  articles = cur.fetchall()
  cur.execute(
      "SELECT COUNT(*) AS count FROM movements WHERE article_id IS NULL AND date < %s",
      (period_end,),
  )
  orphaned_movement_count = cur.fetchone()["count"]
  cur.close()

  movement_cur = db.cursor(
      name=f"monthly_close_{secrets.token_hex(8)}"
  )
  movement_cur.itersize = 1000
  movement_cur.execute("""
      SELECT article_id, type, quantity, unit_price,
             unit_price_estimated, date
      FROM movements
      WHERE article_id IS NOT NULL AND date <= CURRENT_TIMESTAMP
      ORDER BY article_id, date, id
  """)
  monthly_close_rows, totals = build_monthly_close_rows(
      articles, movement_cur, period_start, period_end
  )
  movement_cur.close()

  return render_template_string(
      MONTHLY_CLOSE_TEMPLATE,
      active_page="monthly_close",
      total_stock_value=calculate_total_stock_value(),
      monthly_close_rows=monthly_close_rows,
      month_key=month_key,
      current_month_key=current_month_key,
      period_label=period_label,
      period_start_label=month_start_date.strftime("%d/%m/%Y"),
      period_end_label=period_end_date.strftime("%d/%m/%Y"),
      generated_at=datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
      current_month=month_start_date == current_month_start,
      orphaned_movement_count=orphaned_movement_count,
      **totals,
  )


@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_article(id):
  db = get_db()
  cur = db.cursor()

  if request.method == "POST":
    name = request.form.get("name", "").strip()
    if not name:
      abort(400, description="Le nom de l'article est obligatoire.")
    reference = request.form.get("reference")
    quantity = form_integer("quantity", minimum=0)
    min_threshold = form_integer("min_threshold", default=2, minimum=0)
    price = form_price()
    is_estimated_price = 1 if "is_estimated_price" in request.form else 0
    supplier = request.form.get("supplier")
    invoice_number = request.form.get("invoice_number")
    entry_date = request.form.get("entry_date") or None
    if entry_date:
      try:
        entry_date = datetime.date.fromisoformat(entry_date)
      except ValueError:
        abort(400, description="La date d'entrée est invalide.")
    location_id = optional_integer(request.form.get("location_id"), "location_id")
    equipment_id = optional_integer(request.form.get("equipment_id"), "equipment_id")

    cur.execute("SELECT quantity, price FROM articles WHERE id = %s FOR UPDATE", (id,))
    article = cur.fetchone()
    if article is None:
      abort(404)
    old_quantity = article["quantity"]
    filename = save_uploaded_image(request.files.get("photo"))
    if filename:
      cur.execute(
          """
              UPDATE articles SET name=%s, reference=%s, quantity=%s, min_threshold=%s, price=%s,
              is_estimated_price=%s, supplier=%s, invoice_number=%s, entry_date=%s, location_id=%s,
              equipment_id=%s, image_filename=%s WHERE id=%s
          """,
          (
              name, reference, quantity, min_threshold, price, is_estimated_price,
              supplier, invoice_number, entry_date, location_id, equipment_id, filename, id,
          ),
      )
    else:
      cur.execute(
          """
              UPDATE articles SET name=%s, reference=%s, quantity=%s, min_threshold=%s, price=%s,
              is_estimated_price=%s, supplier=%s, invoice_number=%s, entry_date=%s, location_id=%s,
              equipment_id=%s WHERE id=%s
          """,
          (
              name, reference, quantity, min_threshold, price, is_estimated_price,
              supplier, invoice_number, entry_date, location_id, equipment_id, id,
          ),
      )
    quantity_delta = quantity - old_quantity
    if quantity_delta:
      cur.execute(
          """
              INSERT INTO movements
                  (article_id, type, quantity, unit_price, unit_price_estimated, reason, date)
              VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
          """,
          (
              id,
              "ENTREE" if quantity_delta > 0 else "SORTIE",
              abs(quantity_delta),
              price,
              bool(is_estimated_price),
              "Correction de stock via modification de l'article",
          ),
      )

    db.commit()
    cur.close()
    return redirect(url_for("edit_article", id=id))

  cur.execute("SELECT * FROM articles WHERE id = %s", (id,))
  article = cur.fetchone()
  if article is None:
    cur.close()
    abort(404)
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()

  return render_template_string(
      EDIT_ARTICLE_TEMPLATE,
      active_page="stock",
      print_qr_page=True,
      article=article,
      locations=locations,
      equipment=equipment,
      total_stock_value=total_val,
      article_created=request.args.get("created") == "1",
      qr_code_data=article_qr_code_data(
          APP_BASE_URL + url_for(
              "entry_form", article_id=id, mode="choose"
          )
      ),
  )


@app.route("/settings")
def settings_view():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("""
        SELECT e.*, l.name as loc_name 
        FROM equipment e 
        LEFT JOIN locations l ON e.location_id = l.id 
        ORDER BY e.name
    """)
  equipment = cur.fetchall()
  cur.execute(
      "SELECT id, username, role, active FROM users ORDER BY username"
  )
  users = cur.fetchall() if g.current_user["role"] == "admin" else []
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      SETTINGS_TEMPLATE,
      active_page="settings",
      locations=locations,
      equipment=equipment,
      users=users,
      current_user=g.current_user,
      total_stock_value=total_val,
  )


@app.route("/users/add", methods=["POST"])
def add_user():
  require_admin()
  username = request.form.get("username", "").strip().lower()
  password = request.form.get("password", "")
  role = request.form.get("role", "user")
  if not re.fullmatch(r"[\w.@+-]{3,64}", username):
    abort(
        400,
        description=(
            "Identifiant invalide : utilisez 3 à 64 caractères sans espace "
            "(lettres, chiffres, point, tiret, souligné, @ ou +)."
        ),
    )
  if len(password) < 12:
    abort(400, description="Le mot de passe doit contenir au moins 12 caractères.")
  if role not in {"user", "admin"}:
    abort(400, description="Rôle utilisateur invalide.")

  cur = get_db().cursor()
  cur.execute(
      """
          INSERT INTO users (username, password_hash, role)
          VALUES (%s, %s, %s)
          ON CONFLICT (username) DO NOTHING
          RETURNING id
      """,
      (username, hash_password(password), role),
  )
  if cur.fetchone() is None:
    cur.close()
    flash("Cet identifiant existe déjà.", "error")
    return redirect(url_for("settings_view"))
  get_db().commit()
  cur.close()
  flash(f"Le compte « {username} » a été créé.", "success")
  return redirect(url_for("settings_view"))


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
def toggle_user(user_id):
  require_admin()
  if user_id == g.current_user["id"]:
    abort(400, description="Vous ne pouvez pas désactiver votre propre compte.")

  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT pg_advisory_xact_lock(73401219078124::bigint)")
  cur.execute(
      "SELECT role, active FROM users WHERE id = %s FOR UPDATE",
      (user_id,),
  )
  account = cur.fetchone()
  if account is None:
    cur.close()
    abort(404)
  if account["role"] == "admin" and account["active"]:
    cur.execute("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = TRUE")
    if cur.fetchone()["count"] <= 1:
      db.rollback()
      cur.close()
      abort(400, description="Impossible de désactiver le dernier administrateur actif.")
  cur.execute("UPDATE users SET active = NOT active WHERE id = %s", (user_id,))
  db.commit()
  cur.close()
  flash("Le statut du compte a été modifié.", "success")
  return redirect(url_for("settings_view"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
def reset_user_password(user_id):
  require_admin()
  password = request.form.get("password", "")
  if len(password) < 12:
    abort(400, description="Le mot de passe doit contenir au moins 12 caractères.")
  cur = get_db().cursor()
  cur.execute(
      "UPDATE users SET password_hash = %s WHERE id = %s RETURNING username",
      (hash_password(password), user_id),
  )
  account = cur.fetchone()
  if account is None:
    cur.close()
    abort(404)
  get_db().commit()
  cur.close()
  flash(f"Le mot de passe du compte « {account['username']} » a été réinitialisé.", "success")
  return redirect(url_for("settings_view"))


@app.route("/add_location", methods=["POST"])
def add_location():
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom du lieu est obligatoire.")
  cur.execute("INSERT INTO locations (name) VALUES (%s)", (name,))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/edit_location/<int:id>", methods=["POST"])
def edit_location(id):
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom du lieu est obligatoire.")
  cur.execute("UPDATE locations SET name = %s WHERE id = %s", (name, id))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/delete_location/<int:id>", methods=["POST"])
def delete_location(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM locations WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/add_equipment", methods=["POST"])
def add_equipment():
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom de l'équipement est obligatoire.")
  location_id = optional_integer(request.form.get("location_id"), "location_id")
  cur.execute(
      "INSERT INTO equipment (name, location_id) VALUES (%s, %s)",
      (name, location_id),
  )
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/edit_equipment/<int:id>", methods=["POST"])
def edit_equipment(id):
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom de l'équipement est obligatoire.")
  location_id = optional_integer(request.form.get("location_id"), "location_id")
  cur.execute(
      "UPDATE equipment SET name = %s, location_id = %s WHERE id = %s",
      (name, location_id, id),
  )
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/delete_equipment/<int:id>", methods=["POST"])
def delete_equipment(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM equipment WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("settings_view"))


@app.route("/add", methods=["POST"])
def add_article():
  db = get_db()
  cur = db.cursor()
  name = request.form.get("name", "").strip()
  if not name:
    abort(400, description="Le nom de l'article est obligatoire.")
  reference = request.form.get("reference")
  quantity = form_integer("quantity", default=1, minimum=0)
  min_threshold = form_integer("min_threshold", default=2, minimum=0)
  price = form_price()
  is_estimated_price = 1 if "is_estimated_price" in request.form else 0
  supplier = request.form.get("supplier")
  invoice_number = request.form.get("invoice_number")
  entry_date = request.form.get("entry_date") or datetime.date.today()
  if isinstance(entry_date, str):
    try:
      entry_date = datetime.date.fromisoformat(entry_date)
    except ValueError:
      abort(400, description="La date d'entrée est invalide.")
  location_id = optional_integer(request.form.get("location_id"), "location_id")
  equipment_id = optional_integer(request.form.get("equipment_id"), "equipment_id")
  reason = f"Entrée - Fournisseur: {supplier or 'N/C'} | Facture: {invoice_number or 'N/C'}"

  filename = save_uploaded_image(request.files.get("photo"))

  cur.execute(
      """
        INSERT INTO articles (name, reference, quantity, min_threshold, price, is_estimated_price, supplier, invoice_number, entry_date, location_id, equipment_id, image_filename) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
    """,
      (
          name,
          reference,
          quantity,
          min_threshold,
          price,
          is_estimated_price,
          supplier,
          invoice_number,
          entry_date,
          location_id,
          equipment_id,
          filename,
      ),
  )
  article_id = cur.fetchone()["id"]

  cur.execute(
      """
        INSERT INTO movements
            (article_id, type, quantity, unit_price, unit_price_estimated,
             supplier, invoice_number, reason, date)
        VALUES (%s, 'ENTREE', %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
    """,
      (
          article_id, quantity, price, bool(is_estimated_price),
          supplier, invoice_number, reason,
      ),
  )
  db.commit()
  cur.close()
  return redirect(url_for("edit_article", id=article_id, created=1))


@app.route("/movement_entry", methods=["POST"])
def movement_entry():
  db = get_db()
  cur = db.cursor()
  article_id = form_integer("article_id", minimum=1)
  qty = form_integer("qty", minimum=1)
  price = form_price()
  supplier = request.form.get("supplier", "").strip() or None
  invoice_number = request.form.get("invoice_number", "").strip() or None
  reason = "Réapprovisionnement"

  cur.execute(
      """
          UPDATE articles
          SET quantity = quantity + %s,
              price = %s,
              is_estimated_price = 0,
              supplier = COALESCE(%s, supplier),
              invoice_number = %s
          WHERE id = %s
          RETURNING id
      """,
      (qty, price, supplier, invoice_number, article_id),
  )
  article = cur.fetchone()
  if article is None:
    db.rollback()
    cur.close()
    abort(404, description="Article introuvable.")
  cur.execute(
      """
          INSERT INTO movements
              (article_id, type, quantity, unit_price, unit_price_estimated,
               supplier, invoice_number, reason, date)
          VALUES (%s, 'ENTREE', %s, %s, FALSE, %s, %s, %s, CURRENT_TIMESTAMP)
      """,
      (article_id, qty, price, supplier, invoice_number, reason),
  )
  db.commit()
  cur.close()
  return redirect(url_for("entry_form", article_id=article_id, mode="choose"))


@app.route("/movement_exit", methods=["POST"])
def movement_exit():
  db = get_db()
  cur = db.cursor()
  article_id = form_integer("article_id", minimum=1)
  qty = form_integer("qty", minimum=1)
  reason = request.form.get("reason", "").strip()
  if not reason:
    abort(400, description="Le motif de sortie est obligatoire.")

  cur.execute(
      """
          UPDATE articles SET quantity = quantity - %s
          WHERE id = %s AND quantity >= %s
          RETURNING id, price, is_estimated_price
      """,
      (qty, article_id, qty),
  )
  article = cur.fetchone()
  if article is None:
    db.rollback()
    abort(400, description="Article inexistant ou stock insuffisant.")
  cur.execute(
      """
          INSERT INTO movements
              (article_id, type, quantity, unit_price, unit_price_estimated, reason, date)
          VALUES (%s, 'SORTIE', %s, %s, %s, %s, CURRENT_TIMESTAMP)
      """,
      (
          article_id,
          qty,
          article["price"] or 0.0,
          bool(article["is_estimated_price"]),
          reason,
      ),
  )
  db.commit()
  cur.close()

  return redirect(url_for("stock_view"))


@app.route("/update/<int:id>", methods=["POST"])
def update_quantity(id):
  db = get_db()
  cur = db.cursor()
  action = request.form.get("action")
  if action not in {"plus", "minus"}:
    abort(400, description="Action de mise à jour invalide.")
  cur.execute(
      "SELECT quantity, price, is_estimated_price FROM articles WHERE id = %s FOR UPDATE",
      (id,),
  )
  item = cur.fetchone()
  if item is None:
    abort(404)
  current_qty = item["quantity"]
  if action == "minus" and current_qty == 0:
    abort(400, description="Le stock est déjà à zéro.")
  delta = 1 if action == "plus" else -1
  cur.execute("UPDATE articles SET quantity = quantity + %s WHERE id = %s", (delta, id))
  cur.execute(
      """
          INSERT INTO movements
              (article_id, type, quantity, unit_price, unit_price_estimated, reason, date)
          VALUES (%s, %s, 1, %s, %s, %s, CURRENT_TIMESTAMP)
      """,
      (
          id,
          "ENTREE" if delta > 0 else "SORTIE",
          item["price"] or 0.0,
          bool(item["is_estimated_price"]),
          "Ajustement manuel du stock",
      ),
  )
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


@app.route("/delete/<int:id>", methods=["POST"])
def delete_article(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM articles WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=10000, debug=False)
