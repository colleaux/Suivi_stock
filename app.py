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


# --- CHARTE GRAPHIQUE CORPORATE & LAYOUT UNIFIÉ ---

LAYOUT_HEADER = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion & Suivi de Stock</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            .no-print { display: none !important; }
            body { background: white !important; font-size: 11px; }
            .print-table { border: 1px solid #CBD5E1 !important; }
        }
    </style>
</head>
<body class="bg-slate-100 text-slate-800 font-sans antialiased min-h-screen flex flex-col">

    <!-- Header / Navbar Principal -->
    <header class="bg-slate-900 text-white shadow-md border-b border-slate-800 no-print">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <!-- Branding -->
                <div class="flex items-center gap-3">
                    <div class="w-8 h-8 bg-slate-700 rounded-lg flex items-center justify-center font-bold text-slate-200">
                        📦
                    </div>
                    <div>
                        <a href="/" class="text-base font-bold tracking-tight text-white block">SUIVI INVENTAIRE</a>
                        <span class="text-[10px] text-slate-400 font-medium">CAPITAL IMMOBILISÉ : {{ "%.2f"|format(total_stock_value or 0) }} €</span>
                    </div>
                </div>

                <!-- Navigation 3 Liens Clés -->
                <nav class="flex space-x-1 sm:space-x-2">
                    <a href="/entry" class="px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center gap-1.5 {% if active_page == 'entry' %}bg-slate-800 text-amber-400 border border-slate-700{% else %}text-slate-300 hover:bg-slate-800 hover:text-white{% endif %}">
                        <span>✏️</span> Saisie
                    </a>
                    <a href="/stock" class="px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center gap-1.5 {% if active_page == 'stock' %}bg-slate-800 text-amber-400 border border-slate-700{% else %}text-slate-300 hover:bg-slate-800 hover:text-white{% endif %}">
                        <span>📊</span> Suivi & Rapport
                    </a>
                    <a href="/settings" class="px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center gap-1.5 {% if active_page == 'settings' %}bg-slate-800 text-amber-400 border border-slate-700{% else %}text-slate-300 hover:bg-slate-800 hover:text-white{% endif %}">
                        <span>⚙️</span> Réglages
                    </a>
                </nav>
            </div>
        </div>
    </header>

    <!-- Content Container -->
    <main class="flex-grow max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
"""

LAYOUT_FOOTER = """
    </main>

    <!-- Footer -->
    <footer class="bg-slate-900 text-slate-500 text-[11px] py-4 border-t border-slate-800 text-center no-print mt-auto">
        Système de Gestion de Stock & Operations | Facility Management
    </footer>
</body>
</html>
"""

# --- 1. PAGE DE SAISIE DE DONNÉES (ENTRÉE / SORTIE) ---
ENTRY_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-3xl mx-auto space-y-6">
        <!-- Bandeau d'en-tête -->
        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-4 flex justify-between items-center">
            <div>
                <h1 class="text-base font-bold text-slate-900">Saisie des Mouvements</h1>
                <p class="text-xs text-slate-500">Enregistrez de nouvelles entrées ou consommez du matériel pour intervention</p>
            </div>
        </div>

        <!-- Formulaire avec Onglets d'action -->
        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div class="bg-slate-900 px-6 py-3 border-b border-slate-800 flex gap-4">
                <span class="text-xs font-bold text-white uppercase tracking-wider">Formulaire d'enregistrement</span>
            </div>
            
            <div class="p-6 space-y-6">
                <!-- Section Entrée -->
                <div class="space-y-4">
                    <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-500"></span> Entrée en stock / Nouvel Article
                    </h2>
                    
                    <form action="/add" method="POST" enctype="multipart/form-data" class="space-y-4">
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            <div class="sm:col-span-2">
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Nom de l'article *</label>
                                <input type="text" name="name" required placeholder="ex: Disjoncteur 16A" class="w-full text-xs p-2.5 border border-slate-300 rounded focus:ring-1 focus:ring-slate-900 outline-none">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                                <input type="text" name="reference" placeholder="ex: REF-8840" class="w-full text-xs p-2.5 border border-slate-300 rounded focus:ring-1 focus:ring-slate-900 outline-none">
                            </div>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité ajoutée *</label>
                                <input type="number" name="quantity" value="1" min="1" required class="w-full text-xs p-2.5 border border-slate-300 rounded focus:ring-1 focus:ring-slate-900 outline-none font-bold">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Prix unitaire (€)</label>
                                <input type="number" step="0.01" name="price" value="0.00" required class="w-full text-xs p-2.5 border border-slate-300 rounded focus:ring-1 focus:ring-slate-900 outline-none">
                            </div>
                            <div class="flex items-end pb-2">
                                <label class="flex items-center gap-2 text-xs text-slate-600 cursor-pointer">
                                    <input type="checkbox" name="is_estimated_price" value="1" class="rounded border-slate-300 text-slate-900">
                                    <span>Prix estimé</span>
                                </label>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Emplacement du stock</label>
                                <select name="location_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white focus:ring-1 focus:ring-slate-900 outline-none">
                                    <option value="">-- Sélectionner un lieu --</option>
                                    {% for loc in locations %}
                                    <option value="{{ loc.id }}">{{ loc.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Équipement associé</label>
                                <select name="equipment_id" class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white focus:ring-1 focus:ring-slate-900 outline-none">
                                    <option value="">-- Sélectionner une machine --</option>
                                    {% for eq in equipment %}
                                    <option value="{{ eq.id }}">{{ eq.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                        </div>

                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Motif / Origine</label>
                            <input type="text" name="reason" placeholder="ex: Livré par fournisseur" class="w-full text-xs p-2.5 border border-slate-300 rounded focus:ring-1 focus:ring-slate-900 outline-none">
                        </div>

                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Photo de l'article</label>
                            <input type="file" name="photo" accept="image/*" class="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-slate-100 file:text-slate-700 hover:file:bg-slate-200">
                        </div>

                        <button type="submit" class="w-full bg-slate-900 hover:bg-slate-800 text-white font-semibold py-2.5 rounded text-xs transition shadow-sm">
                            Valider l'Entrée
                        </button>
                    </form>
                </div>

                <hr class="border-slate-200 my-6">

                <!-- Section Sortie -->
                <div class="space-y-4">
                    <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-amber-500"></span> Sortie de stock / Consommation
                    </h2>

                    <form action="/movement_exit" method="POST" class="space-y-4">
                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Article à prélever *</label>
                            <select name="article_id" required class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white focus:ring-1 focus:ring-slate-900 outline-none">
                                <option value="">-- Choisir une pièce --</option>
                                {% for item in articles %}
                                <option value="{{ item.id }}">{{ item.name }} (Réf: {{ item.reference or 'N/C' }}) | Qte dispo: {{ item.quantity }}</option>
                                {% endfor %}
                            </select>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Quantité sortie *</label>
                                <input type="number" name="qty" value="1" min="1" required class="w-full text-xs p-2.5 border border-slate-300 rounded font-bold">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Motif / Intervenant *</label>
                                <input type="text" name="reason" required placeholder="ex: Dépannage pompe" class="w-full text-xs p-2.5 border border-slate-300 rounded">
                            </div>
                        </div>

                        <button type="submit" class="w-full bg-slate-700 hover:bg-slate-800 text-white font-semibold py-2.5 rounded text-xs transition shadow-sm">
                            Enregistrer la Sortie
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- 2. PAGE DE SUIVI DES DONNÉES & TABLEAU DE BORD ---
STOCK_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="space-y-6">
        <!-- Bandeau Synthèse -->
        <div class="bg-slate-900 text-white rounded-lg p-5 shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
                <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Valeur totale de l'inventaire</span>
                <div class="text-2xl font-extrabold text-white mt-0.5">{{ "%.2f"|format(total_stock_value) }} €</div>
            </div>
            <div class="flex gap-2 no-print">
                <button onclick="window.print()" class="bg-slate-800 hover:bg-slate-700 text-xs font-semibold px-4 py-2 rounded border border-slate-700 transition">
                    🖨️ Imprimer / PDF
                </button>
            </div>
        </div>

        <!-- Filtres Tableur -->
        <div class="bg-white p-4 rounded-lg border border-slate-200 shadow-sm no-print">
            <form method="GET" action="/stock" class="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <input type="text" name="search" value="{{ search_query or '' }}" placeholder="Rechercher désignation..." class="text-xs p-2 border border-slate-300 rounded outline-none">
                <select name="loc_filter" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="">Tous les emplacements</option>
                    {% for loc in locations %}
                    <option value="{{ loc.id }}" {% if current_loc == loc.id|string %}selected{% endif %}>{{ loc.name }}</option>
                    {% endfor %}
                </select>
                <select name="eq_filter" class="text-xs p-2 border border-slate-300 rounded bg-white">
                    <option value="">Tous les équipements</option>
                    {% for eq in equipment %}
                    <option value="{{ eq.id }}" {% if current_eq == eq.id|string %}selected{% endif %}>{{ eq.name }}</option>
                    {% endfor %}
                </select>
                <div class="flex gap-2">
                    <button type="submit" class="flex-1 bg-slate-900 text-white text-xs font-semibold py-2 rounded hover:bg-slate-800">Filtrer</button>
                    {% if search_query or current_loc or current_eq %}
                    <a href="/stock" class="px-3 py-2 text-xs bg-slate-100 text-slate-600 rounded hover:bg-slate-200 flex items-center">Effacer</a>
                    {% endif %}
                </div>
            </form>
        </div>

        <!-- Tableau inspiré de la charte Excel -->
        <div class="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse text-xs print-table">
                    <thead>
                        <tr class="bg-slate-900 text-white border-b border-slate-800 uppercase font-semibold text-[11px] tracking-wider">
                            <th class="p-3 border-r border-slate-800">Statut</th>
                            <th class="p-3 border-r border-slate-800">N° Article</th>
                            <th class="p-3 border-r border-slate-800">Nom de l'article</th>
                            <th class="p-3 border-r border-slate-800">Emplacement</th>
                            <th class="p-3 border-r border-slate-800">Équipement</th>
                            <th class="p-3 border-r border-slate-800 text-right">Prix Unitaire</th>
                            <th class="p-3 border-r border-slate-800 text-center">Quantité</th>
                            <th class="p-3 text-right">Valeur Totale</th>
                            <th class="p-3 text-center no-print">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200">
                        {% for item in articles %}
                        <!-- Alerte visuelle Corail/Pêche pour stock critique (<=2) -->
                        <tr class="{% if item.quantity <= 2 %}bg-rose-50/80 hover:bg-rose-100/80{% else %}hover:bg-slate-50{% endif %} transition">
                            <td class="p-3 font-bold border-r border-slate-200">
                                {% if item.quantity <= 2 %}
                                <span class="px-2 py-0.5 rounded text-[10px] bg-rose-200 text-rose-900 font-bold uppercase">RECOMMANDER</span>
                                {% else %}
                                <span class="px-2 py-0.5 rounded text-[10px] bg-emerald-100 text-emerald-800 font-semibold uppercase">OK</span>
                                {% endif %}
                            </td>
                            <td class="p-3 font-mono text-slate-500 border-r border-slate-200">{{ item.reference or '-' }}</td>
                            <td class="p-3 font-semibold text-slate-900 border-r border-slate-200">
                                {{ item.name }}
                                {% if item.is_estimated_price %}
                                <span class="text-[9px] text-amber-700 bg-amber-50 px-1 rounded ml-1 font-normal">(Est.)</span>
                                {% endif %}
                            </td>
                            <td class="p-3 text-slate-600 border-r border-slate-200">{{ item.loc_name or 'Non assigné' }}</td>
                            <td class="p-3 text-slate-600 border-r border-slate-200">{{ item.eq_name or '-' }}</td>
                            <td class="p-3 text-right text-slate-700 border-r border-slate-200 font-mono">{{ "%.2f"|format(item.price) }} €</td>
                            <td class="p-3 text-center font-bold text-slate-900 border-r border-slate-200">{{ item.quantity }}</td>
                            <td class="p-3 text-right font-bold text-slate-900 font-mono">{{ "%.2f"|format(item.quantity * item.price) }} €</td>
                            <td class="p-3 text-center no-print">
                                <div class="flex items-center justify-center gap-2">
                                    <form action="/update/{{ item.id }}" method="POST" class="inline">
                                        <input type="hidden" name="action" value="minus">
                                        <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">-</button>
                                    </form>
                                    <form action="/update/{{ item.id }}" method="POST" class="inline">
                                        <input type="hidden" name="action" value="plus">
                                        <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">+</button>
                                    </form>
                                    <form action="/delete/{{ item.id }}" method="POST" onsubmit="return confirm('Supprimer ?');" class="inline ml-2">
                                        <button type="submit" class="text-rose-600 hover:underline text-xs">Suppr</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="9" class="p-6 text-center text-slate-400 text-xs">Aucune donnée disponible dans le tableau.</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- 3. PAGE DE RÉGLAGES (GESTION LIEUX & ÉQUIPEMENTS) ---
SETTINGS_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-white rounded-lg border border-slate-200 p-4 shadow-sm">
            <h1 class="text-base font-bold text-slate-900">Réglages & Configuration</h1>
            <p class="text-xs text-slate-500">Gérez les emplacements physiques de stockage et les équipements/machines associés</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- Gestion des Emplacements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    📍 Emplacements de Stockage
                </h2>
                <form action="/add_location" method="POST" class="flex gap-2">
                    <input type="text" name="name" required placeholder="ex: Atelier A, Étagère 2" class="flex-grow text-xs p-2 border border-slate-300 rounded outline-none">
                    <button type="submit" class="bg-slate-900 hover:bg-slate-800 text-white px-3 py-2 rounded text-xs font-semibold">Ajouter</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for loc in locations %}
                    <div class="py-2.5 flex justify-between items-center">
                        <span class="font-semibold text-slate-700">{{ loc.name }}</span>
                        <form action="/delete_location/{{ loc.id }}" method="POST" onsubmit="return confirm('Supprimer cet emplacement ?');">
                            <button type="submit" class="text-rose-600 hover:underline text-[11px]">Supprimer</button>
                        </form>
                    </div>
                    {% else %}
                    <p class="text-slate-400 text-xs italic">Aucun lieu configuré.</p>
                    {% endfor %}
                </div>
            </div>

            <!-- Gestion des Équipements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    ⚙️ Équipements & Machines
                </h2>
                <form action="/add_equipment" method="POST" class="space-y-2">
                    <input type="text" name="name" required placeholder="Nom de l'équipement..." class="w-full text-xs p-2 border border-slate-300 rounded outline-none">
                    <select name="location_id" required class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                        <option value="">-- Rattacher à un emplacement --</option>
                        {% for loc in locations %}
                        <option value="{{ loc.id }}">{{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="w-full bg-slate-900 hover:bg-slate-800 text-white py-2 rounded text-xs font-semibold">Ajouter l'Équipement</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for eq in equipment %}
                    <div class="py-2.5 flex justify-between items-center">
                        <div>
                            <span class="font-semibold text-slate-800 block">{{ eq.name }}</span>
                            <span class="text-[10px] text-slate-500">📍 {{ eq.loc_name or 'Aucun lieu' }}</span>
                        </div>
                        <form action="/delete_equipment/{{ eq.id }}" method="POST" onsubmit="return confirm('Supprimer cet équipement ?');">
                            <button type="submit" class="text-rose-600 hover:underline text-[11px]">Supprimer</button>
                        </form>
                    </div>
                    {% else %}
                    <p class="text-slate-400 text-xs italic">Aucun équipement configuré.</p>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
"""
    + LAYOUT_FOOTER
)


# --- ROUTES FLASK CORRESPONDANTES ---


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
  return render_template_string(
      ENTRY_TEMPLATE,
      active_page="entry",
      locations=locations,
      equipment=equipment,
      articles=articles,
      total_stock_value=total_val,
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
      active_page="stock",
      locations=locations,
      equipment=equipment,
      articles=articles,
      search_query=search_query,
      current_loc=loc_filter,
      current_eq=eq_filter,
      total_stock_value=filtered_total_val,
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
      active_page="settings",
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
  location_id = request.form.get("location_id") or None
  if name:
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
  reference = request.form.get("reference")
  quantity = int(request.form.get("quantity", 1))
  price = float(request.form.get("price") or 0.0)
  is_estimated_price = 1 if "is_estimated_price" in request.form else 0
  location_id = request.form.get("location_id") or None
  equipment_id = request.form.get("equipment_id") or None
  reason = request.form.get("reason") or "Entrée stock"

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


@app.route("/delete/<int:id>", methods=["POST"])
def delete_article(id):
  db = get_db()
  cur = db.cursor()
  cur.execute("DELETE FROM articles WHERE id = %s", (id,))
  db.commit()
  cur.close()
  return redirect(url_for("stock_view"))


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=10000, debug=True)
