import os
import psycopg
from psycopg.rows import dict_row
from flask import Flask, g, redirect, render_template_string, request, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
  return (
      "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
  )


DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
  if "db" not in g:
    g.db = psycopg.connect(DATABASE_URL, row_factory=dict_row)
  return g.db


@app.teardown_appcontext
def close_connection(exception):
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
            location_id INTEGER REFERENCES locations(id) ON DELETE SET NULL,
            equipment_id INTEGER REFERENCES equipment(id) ON DELETE SET NULL,
            image_filename TEXT
        );
        CREATE TABLE IF NOT EXISTS movements (
            id SERIAL PRIMARY KEY,
            article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            reason TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
  cursor.close()
  conn.close()


with app.app_context():
  init_db()


# --- TEMPLATES HTML (Placeholders) ---
HOME_TEMPLATE = ""
SUMMARY_TEMPLATE = ""
DETAILED_INVENTORY_TEMPLATE = ""
ENTRY_TEMPLATE = ""
EXIT_TEMPLATE = ""
STOCK_TEMPLATE = ""
EDIT_TEMPLATE = ""
HISTORY_TEMPLATE = ""
SETTINGS_TEMPLATE = ""


# --- CALCUL GLOBAL ---


def calculate_total_stock_value(articles_list=None):
  db = get_db()
  cur = db.cursor()
  if articles_list is None:
    cur.execute("SELECT quantity, price FROM articles")
    articles_list = cur.fetchall()
  cur.close()
  return sum(
      (item["quantity"] * (item["price"] or 0.0)) for item in articles_list
  )


# --- ROUTES UNIQUE ---


@app.route("/")
def home():
  total_val = calculate_total_stock_value()
  return render_template_string(HOME_TEMPLATE, total_stock_value=total_val)


@app.route("/summary")
def summary_view():
  db = get_db()
  cur = db.cursor()
  total_val = calculate_total_stock_value()

  cur.execute("""
        SELECT l.name as location_name, SUM(a.quantity * a.price) as loc_value
        FROM locations l
        LEFT JOIN articles a ON a.location_id = l.id
        GROUP BY l.id, l.name
        ORDER BY loc_value DESC
    """)
  summary_locations = cur.fetchall()

  cur.execute("""
        SELECT e.name as equipment_name, SUM(a.quantity * a.price) as eq_value
        FROM equipment e
        LEFT JOIN articles a ON a.equipment_id = e.id
        GROUP BY e.id, e.name
        ORDER BY eq_value DESC
    """)
  summary_equipment = cur.fetchall()
  cur.close()

  return render_template_string(
      SUMMARY_TEMPLATE,
      total_stock_value=total_val,
      summary_locations=summary_locations,
      summary_equipment=summary_equipment,
  )


@app.route("/detailed_inventory")
def detailed_inventory_view():
  db = get_db()
  cur = db.cursor()
  total_val = calculate_total_stock_value()
  cur.execute("""
        SELECT a.*, l.name as loc_name, e.name as eq_name 
        FROM articles a
        LEFT JOIN locations l ON a.location_id = l.id
        LEFT JOIN equipment e ON a.equipment_id = e.id
        ORDER BY a.name
    """)
  articles = cur.fetchall()
  cur.close()

  return render_template_string(
      DETAILED_INVENTORY_TEMPLATE,
      total_stock_value=total_val,
      articles=articles,
  )


@app.route("/entry")
def entry_form():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment")
  equipment = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      ENTRY_TEMPLATE,
      locations=locations,
      equipment=equipment,
      total_stock_value=total_val,
  )


@app.route("/exit")
def exit_form():
  db = get_db()
  cur = db.cursor()
  cur.execute("""
        SELECT a.*, l.name as loc_name 
        FROM articles a 
        LEFT JOIN locations l ON a.location_id = l.id 
        ORDER BY a.name
    """)
  articles = cur.fetchall()
  cur.execute("SELECT * FROM equipment")
  equipment = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      EXIT_TEMPLATE,
      articles=articles,
      equipment=equipment,
      total_stock_value=total_val,
  )


@app.route("/stock")
def stock_view():
  db = get_db()
  cur = db.cursor()
  cur.execute("SELECT * FROM locations")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment")
  equipment = cur.fetchall()

  search_query = request.args.get("search", "").strip()
  loc_filter = request.args.get("loc_filter")
  eq_filter = request.args.get("eq_filter")

  query = """
        SELECT a.*, l.name as loc_name, e.name as eq_name 
        FROM articles a
        LEFT JOIN locations l ON a.location_id = l.id
        LEFT JOIN equipment e ON a.equipment_id = e.id
        WHERE 1=1
    """
  params = []

  if search_query:
    query += " AND (a.name ILIKE %s OR a.reference ILIKE %s)"
    params.extend([f"%{search_query}%", f"%{search_query}%"])
  if loc_filter:
    query += " AND a.location_id = %s"
    params.append(loc_filter)
  if eq_filter:
    query += " AND a.equipment_id = %s"
    params.append(eq_filter)

  query += " ORDER BY a.name"
  cur.execute(query, params)
  articles = cur.fetchall()
  cur.close()

  filtered_total_val = calculate_total_stock_value(articles)

  return render_template_string(
      STOCK_TEMPLATE,
      locations=locations,
      equipment=equipment,
      articles=articles,
      search_query=search_query,
      current_loc=loc_filter,
      current_eq=eq_filter,
      total_stock_value=filtered_total_val,
  )


@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_article(id):
  db = get_db()
  cur = db.cursor()
  if request.method == "POST":
    name = request.form["name"]
    reference = request.form["reference"]
    quantity = int(request.form["quantity"])
    price = float(request.form["price"] or 0.0)
    is_estimated_price = 1 if "is_estimated_price" in request.form else 0
    location_id = request.form["location_id"]
    equipment_id = request.form["equipment_id"]

    if "photo" in request.files:
      file = request.files["photo"]
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"art_{os.urandom(4).hex()}_{filename}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        cur.execute(
            """
                UPDATE articles SET name = %s, reference = %s, quantity = %s, price = %s, 
                is_estimated_price = %s, location_id = %s, equipment_id = %s, image_filename = %s 
                WHERE id = %s
            """,
            (
                name,
                reference,
                quantity,
                price,
                is_estimated_price,
                location_id,
                equipment_id,
                filename,
                id,
            ),
        )
      else:
        cur.execute(
            """
                UPDATE articles SET name = %s, reference = %s, quantity = %s, price = %s, 
                is_estimated_price = %s, location_id = %s, equipment_id = %s 
                WHERE id = %s
            """,
            (
                name,
                reference,
                quantity,
                price,
                is_estimated_price,
                location_id,
                equipment_id,
                id,
            ),
        )
    db.commit()
    cur.close()
    return redirect(url_for("stock_view"))

  cur.execute("SELECT * FROM articles WHERE id = %s", (id,))
  article = cur.fetchone()
  cur.execute("SELECT * FROM locations ORDER BY name")
  locations = cur.fetchall()
  cur.execute("SELECT * FROM equipment ORDER BY name")
  equipment = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      EDIT_TEMPLATE,
      article=article,
      locations=locations,
      equipment=equipment,
      total_stock_value=total_val,
  )


@app.route("/delete/<int:id>", methods=["POST"])
def delete_article(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM articles WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


@app.route("/history")
def history_view():
  db = get_db()
  cur = db.cursor()
  cur.execute("""
        SELECT m.*, a.name as article_name, a.reference 
        FROM movements m
        LEFT JOIN articles a ON m.article_id = a.id
        ORDER BY m.date DESC
    """)
  movements = cur.fetchall()
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      HISTORY_TEMPLATE, movements=movements, total_stock_value=total_val
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
  cur.close()
  total_val = calculate_total_stock_value()
  return render_template_string(
      SETTINGS_TEMPLATE,
      locations=locations,
      equipment=equipment,
      total_stock_value=total_val,
  )


@app.route("/add_location", methods=["POST"])
def add_location():
  db = get_db()
  cur = db.cursor()
  name = request.form["name"].strip()
  if name:
    cur.execute("INSERT INTO locations (name) VALUES (%s)", (name,))
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
  name = request.form["name"].strip()
  location_id = request.form["location_id"]
  if name and location_id:
    cur.execute(
        "INSERT INTO equipment (name, location_id) VALUES (%s, %s)",
        (name, location_id),
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
  name = request.form["name"]
  reference = request.form["reference"]
  quantity = int(request.form["quantity"])
  price = float(request.form["price"] or 0.0)
  is_estimated_price = 1 if "is_estimated_price" in request.form else 0
  location_id = request.form["location_id"]
  equipment_id = request.form["equipment_id"]
  reason = request.form.get("reason") or "Stock initial / Entrée"

  filename = None
  if "photo" in request.files:
    file = request.files["photo"]
    if file and allowed_file(file.filename):
      filename = secure_filename(file.filename)
      filename = f"art_{os.urandom(4).hex()}_{filename}"
      file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

  cur.execute(
      """
        INSERT INTO articles (name, reference, quantity, price, is_estimated_price, location_id, equipment_id, image_filename) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
    """,
      (
          name,
          reference,
          quantity,
          price,
          is_estimated_price,
          location_id,
          equipment_id,
          filename,
      ),
  )
  article_id = cur.fetchone()["id"]

  cur.execute(
      """
        INSERT INTO movements (article_id, type, quantity, reason) 
        VALUES (%s, 'ENTREE', %s, %s)
    """,
      (article_id, quantity, reason),
  )
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


@app.route("/movement_exit", methods=["POST"])
def movement_exit():
  db = get_db()
  cur = db.cursor()
  article_id = request.form["article_id"]
  qty = int(request.form["qty"])
  reason = request.form["reason"]

  cur.execute("SELECT quantity FROM articles WHERE id = %s", (article_id,))
  item = cur.fetchone()
  if item:
    current_qty = item["quantity"]
    new_qty = max(0, current_qty - qty)

    cur.execute(
        "UPDATE articles SET quantity = %s WHERE id = %s", (new_qty, article_id)
    )
    cur.execute(
        """
            INSERT INTO movements (article_id, type, quantity, reason) 
            VALUES (%s, %s, %s, %s)
        """,
        (article_id, "SORTIE", qty, reason),
    )
    db.commit()
  cur.close()

  return redirect(url_for("stock_view"))


@app.route("/update/<int:id>", methods=["POST"])
def update_quantity(id):
  db = get_db()
  cur = db.cursor()
  action = request.form["action"]
  cur.execute("SELECT quantity FROM articles WHERE id = %s", (id,))
  item = cur.fetchone()
  if item:
    current_qty = item["quantity"]
    new_qty = (
        current_qty + 1 if action == "plus" else max(0, current_qty - 1)
    )
    cur.execute("UPDATE articles SET quantity = %s WHERE id = %s", (new_qty, id))
    db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=10000, debug=True)
