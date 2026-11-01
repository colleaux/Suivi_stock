import os
import sqlite3
from flask import Flask, g, redirect, render_template_string, request, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
DATABASE = "maintenance_stock.db"
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
  return (
      "." in filename
      and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
  )


def get_db():
  db = getattr(g, "_database", None)
  if db is None:
    db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
  return db


@app.teardown_appcontext
def close_connection(exception):
  db = getattr(g, "_database", None)
  if db is not None:
    db.close()


def init_db():
  with app.app_context():
    db = get_db()
    db.executescript("""
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS equipment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                location_id INTEGER,
                FOREIGN KEY (location_id) REFERENCES locations (id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference TEXT,
                name TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL DEFAULT 0.0,
                is_estimated_price INTEGER DEFAULT 0,
                min_threshold INTEGER DEFAULT 2,
                location_id INTEGER,
                equipment_id INTEGER,
                image_filename TEXT,
                FOREIGN KEY (location_id) REFERENCES locations (id) ON DELETE SET NULL,
                FOREIGN KEY (equipment_id) REFERENCES equipment (id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS movements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER,
                type TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                reason TEXT,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (article_id) REFERENCES articles (id) ON DELETE CASCADE
            );
        """)

    # Migrations automatiques
    cursor_art = db.execute("PRAGMA table_info(articles)")
    columns_art = [col["name"] for col in cursor_art.fetchall()]
    if "image_filename" not in columns_art:
      db.execute("ALTER TABLE articles ADD COLUMN image_filename TEXT")
    if "price" not in columns_art:
      db.execute("ALTER TABLE articles ADD COLUMN price REAL DEFAULT 0.0")
    if "is_estimated_price" not in columns_art:
      db.execute(
          "ALTER TABLE articles ADD COLUMN is_estimated_price INTEGER DEFAULT 0"
      )

    cursor_eq = db.execute("PRAGMA table_info(equipment)")
    columns_eq = [col["name"] for col in cursor_eq.fetchall()]
    if "location_id" not in columns_eq:
      db.execute("ALTER TABLE equipment ADD COLUMN location_id INTEGER")

    db.commit()

    cur = db.execute("SELECT COUNT(*) FROM locations")
    if cur.fetchone()[0] == 0:
      db.executescript("""
                INSERT INTO locations (name) VALUES ('Atelier Central'), ('Réserve Technique'), ('Van 1 - Intervention'), ('Local Chaudière');
                INSERT INTO equipment (name, location_id) VALUES ('Chaudière Biomasse', 4), ('Centrale Traitement Air', 1), ('Surpresseur Eau', 2), ('Général / Divers', 1);
                INSERT INTO articles (reference, name, quantity, price, is_estimated_price, min_threshold, location_id, equipment_id) VALUES 
                ('FLT-50', 'Filtre à air 50x50', 4, 15.50, 0, 2, 1, 2),
                ('CR-1200', 'Courroie SPA 1200', 1, 32.00, 1, 2, 2, 1),
                ('SND-PT', 'Sonde PT100', 3, 45.00, 0, 1, 3, 1);
            """)
      db.commit()


# --- TEMPLATES HTML ---

LAYOUT_HEADER = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stock Maintenance</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            body { background: white; color: black; font-size: 11px; }
            .no-print { display: none !important; }
            .print-shadow { box-shadow: none !important; border: 1px solid #ccc !important; }
        }
    </style>
</head>
<body class="bg-gray-100 text-gray-800 pb-16">
    <div class="max-w-md mx-auto p-4">
        <div class="flex justify-between items-center mb-4 bg-blue-600 text-white p-3 rounded-xl shadow no-print">
            <div>
                <h1 class="text-base font-bold">🛠️ Maintenance Stock</h1>
                <p class="text-[11px] opacity-90 font-semibold text-emerald-200">💰 Valeur totale : {{ "%.2f"|format(total_stock_value or 0) }} €</p>
            </div>
            <a href="/" class="bg-blue-700 hover:bg-blue-800 text-white px-3 py-1.5 rounded-lg text-xs font-semibold shadow">🏠 Accueil</a>
        </div>
"""

LAYOUT_FOOTER = """
    </div>
</body>
</html>
"""

# 1. PAGE D'ACCUEIL (Avec Synthèse & Inventaire Détaillé)
HOME_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="space-y-3 mt-2">
            <div class="bg-gradient-to-r from-blue-700 to-indigo-800 text-white p-4 rounded-xl shadow-md text-center">
                <span class="text-xs uppercase tracking-wider text-blue-200 font-semibold">Capital Immobilisé Total</span>
                <div class="text-2xl font-extrabold mt-1">{{ "%.2f"|format(total_stock_value or 0) }} €</div>
            </div>

            <div class="text-center my-2">
                <h2 class="text-sm font-bold text-gray-700">Menu Principal</h2>
            </div>

            <a href="/entry" class="block bg-white border-2 border-emerald-500 p-3.5 rounded-xl shadow-md hover:bg-emerald-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-emerald-100 text-emerald-600 rounded-lg flex items-center justify-center text-lg">➕</div>
                    <div>
                        <h3 class="font-bold text-sm text-emerald-900">Saisie d'une Entrée</h3>
                        <p class="text-[10px] text-gray-500">Réapprovisionner ou créer un article</p>
                    </div>
                </div>
            </a>

            <a href="/exit" class="block bg-white border-2 border-amber-500 p-3.5 rounded-xl shadow-md hover:bg-amber-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-amber-100 text-amber-600 rounded-lg flex items-center justify-center text-lg">➖</div>
                    <div>
                        <h3 class="font-bold text-sm text-amber-900">Saisie d'une Sortie</h3>
                        <p class="text-[10px] text-gray-500">Consommer une pièce pour intervention</p>
                    </div>
                </div>
            </a>

            <a href="/stock" class="block bg-white border-2 border-blue-500 p-3.5 rounded-xl shadow-md hover:bg-blue-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center text-lg">📦</div>
                    <div>
                        <h3 class="font-bold text-sm text-blue-900">État des Stocks</h3>
                        <p class="text-[10px] text-gray-500">Consulter, filtrer, modifier ou supprimer</p>
                    </div>
                </div>
            </a>

            <a href="/summary" class="block bg-white border-2 border-indigo-500 p-3.5 rounded-xl shadow-md hover:bg-indigo-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-indigo-100 text-indigo-600 rounded-lg flex items-center justify-center text-lg">📊</div>
                    <div>
                        <h3 class="font-bold text-sm text-indigo-900">1. Synthèse Financière (Par Lieu/Éq.)</h3>
                        <p class="text-[10px] text-gray-500">Bilan global et totaux par zones & exports PDF</p>
                    </div>
                </div>
            </a>

            <a href="/detailed_inventory" class="block bg-white border-2 border-teal-500 p-3.5 rounded-xl shadow-md hover:bg-teal-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-teal-100 text-teal-600 rounded-lg flex items-center justify-center text-lg">📋</div>
                    <div>
                        <h3 class="font-bold text-sm text-teal-900">2. Inventaire Détaillé Complet</h3>
                        <p class="text-[10px] text-gray-500">Liste complète article par article & export PDF</p>
                    </div>
                </div>
            </a>

            <a href="/history" class="block bg-white border-2 border-purple-500 p-3.5 rounded-xl shadow-md hover:bg-purple-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-purple-100 text-purple-600 rounded-lg flex items-center justify-center text-lg">📜</div>
                    <div>
                        <h3 class="font-bold text-sm text-purple-900">Historique des Mouvements</h3>
                        <p class="text-[10px] text-gray-500">Traçabilité des entrées et sorties</p>
                    </div>
                </div>
            </a>

            <a href="/settings" class="block bg-white border-2 border-gray-500 p-3.5 rounded-xl shadow-md hover:bg-gray-50 transition">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-gray-100 text-gray-700 rounded-lg flex items-center justify-center text-lg">⚙️</div>
                    <div>
                        <h3 class="font-bold text-sm text-gray-900">Gérer Lieux & Équipements</h3>
                        <p class="text-[10px] text-gray-500">Lier équipements aux zones et administrer</p>
                    </div>
                </div>
            </a>
        </div>
"""
    + LAYOUT_FOOTER
)

# 2. PAGE SYNTHÈSE FINANCIÈRE (1er choix)
SUMMARY_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="space-y-4">
            <div class="flex justify-between items-center no-print">
                <h2 class="text-sm font-bold text-indigo-800">📊 Synthèse Financière</h2>
                <button onclick="window.print()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-2 rounded-lg text-xs font-semibold shadow flex items-center gap-1.5">
                    🖨️ Exporter en PDF
                </button>
            </div>

            <div class="bg-white p-4 rounded-xl shadow print-shadow border">
                <h3 class="text-xs font-bold text-gray-500 uppercase tracking-wide mb-2">Bilan Global</h3>
                <div class="flex justify-between items-center text-sm font-bold">
                    <span>Valeur Totale du Stock :</span>
                    <span class="text-emerald-700 text-base">{{ "%.2f"|format(total_stock_value) }} €</span>
                </div>
            </div>

            <div class="bg-white p-4 rounded-xl shadow print-shadow border space-y-3">
                <h3 class="text-xs font-bold text-blue-800 uppercase tracking-wide">📍 Valeur par Lieu de Stockage</h3>
                <div class="divide-y text-xs">
                    {% for row in summary_locations %}
                    <div class="py-2 flex justify-between items-center">
                        <span class="font-medium text-gray-800">{{ row.location_name or 'Non assigné' }}</span>
                        <span class="font-bold text-blue-700">{{ "%.2f"|format(row.loc_value or 0) }} €</span>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="bg-white p-4 rounded-xl shadow print-shadow border space-y-3">
                <h3 class="text-xs font-bold text-purple-800 uppercase tracking-wide">⚙️ Valeur par Équipement</h3>
                <div class="divide-y text-xs">
                    {% for row in summary_equipment %}
                    <div class="py-2 flex justify-between items-center">
                        <span class="font-medium text-gray-800">{{ row.equipment_name or 'Général / Divers' }}</span>
                        <span class="font-bold text-purple-700">{{ "%.2f"|format(row.eq_value or 0) }} €</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
"""
    + LAYOUT_FOOTER
)

# 3. PAGE INVENTAIRE DÉTAILLÉ (2ème choix)
DETAILED_INVENTORY_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="space-y-4">
            <div class="flex justify-between items-center no-print">
                <h2 class="text-sm font-bold text-teal-800">📋 Inventaire Détaillé</h2>
                <button onclick="window.print()" class="bg-teal-600 hover:bg-teal-700 text-white px-3 py-2 rounded-lg text-xs font-semibold shadow flex items-center gap-1.5">
                    🖨️ Exporter en PDF
                </button>
            </div>

            <div class="bg-white p-3 rounded-xl shadow print-shadow border">
                <div class="flex justify-between items-center text-xs font-bold text-gray-700 mb-2 pb-2 border-b">
                    <span>Total articles : {{ articles|length }}</span>
                    <span class="text-emerald-700">Valeur totale : {{ "%.2f"|format(total_stock_value) }} €</span>
                </div>
                
                <div class="space-y-2">
                    {% for item in articles %}
                    <div class="p-2.5 rounded-lg border bg-gray-50 space-y-1">
                        <div class="flex justify-between items-start">
                            <span class="font-bold text-xs text-gray-900">{{ item.name }}</span>
                            <span class="font-bold text-xs text-emerald-700">{{ "%.2f"|format(item.quantity * item.price) }} €</span>
                        </div>
                        <div class="text-[11px] text-gray-600 flex flex-wrap gap-x-3 gap-y-0.5">
                            <span><b>Réf :</b> {{ item.reference or 'N/C' }}</span>
                            <span><b>Qté :</b> {{ item.quantity }}</span>
                            <span><b>Prix :</b> {{ "%.2f"|format(item.price) }} € {% if item.is_estimated_price %}(Est){% endif %}</span>
                        </div>
                        <div class="text-[10px] text-gray-500 flex gap-2 pt-0.5 border-t border-gray-200">
                            <span>📍 {{ item.loc_name or 'Aucun lieu' }}</span>
                            <span>⚙️ {{ item.eq_name or 'Général' }}</span>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
"""
    + LAYOUT_FOOTER
)

# 4. PAGE SAISIE D'UNE ENTRÉE
ENTRY_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="bg-white p-4 rounded-xl shadow mb-4">
            <h2 class="text-sm font-bold text-emerald-700 mb-3">➕ Enregistrer une Entrée / Nouvel Article</h2>
            <form action="/add" method="POST" enctype="multipart/form-data" class="space-y-3">
                <div class="bg-emerald-50 p-3 rounded-lg border border-emerald-100">
                    <label class="block text-xs font-semibold text-emerald-800 mb-1">📸 Photo de l'article (Optionnel)</label>
                    <input type="file" name="photo" accept="image/*" capture="environment" class="w-full text-xs text-gray-600 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-emerald-600 file:text-white">
                </div>
                
                <input type="text" name="name" placeholder="Nom de la pièce / article" required class="w-full p-2 border rounded text-sm">
                
                <div class="grid grid-cols-3 gap-2">
                    <input type="text" name="reference" placeholder="Référence" class="w-full p-2 border rounded text-sm col-span-1">
                    <input type="number" name="quantity" placeholder="Quantité" value="1" min="1" required class="w-full p-2 border rounded text-sm col-span-1">
                    <input type="number" step="0.01" name="price" placeholder="Prix (€)" value="0.00" required class="w-full p-2 border rounded text-sm col-span-1">
                </div>

                <div class="flex items-center gap-2 bg-gray-50 p-2.5 rounded border">
                    <input type="checkbox" id="is_estimated_price" name="is_estimated_price" value="1" class="w-4 h-4 text-blue-600 rounded">
                    <label for="is_estimated_price" class="text-xs font-semibold text-gray-700 cursor-pointer">Il s'agit d'un prix estimé (et non réel)</label>
                </div>

                <div class="grid grid-cols-2 gap-2">
                    <select name="location_id" class="w-full p-2 border rounded text-sm bg-white">
                        {% for loc in locations %}
                        <option value="{{ loc.id }}">📍 {{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <select name="equipment_id" class="w-full p-2 border rounded text-sm bg-white">
                        {% for eq in equipment %}
                        <option value="{{ eq.id }}">⚙️ {{ eq.name }}</option>
                        {% endfor %}
                    </select>
                </div>

                <input type="text" name="reason" placeholder="Motif (ex: Commande fournisseur...)" class="w-full p-2 border rounded text-sm">

                <button type="submit" class="w-full bg-emerald-600 text-white p-2.5 rounded text-sm font-semibold hover:bg-emerald-700">Valider l'entrée</button>
            </form>
        </div>
"""
    + LAYOUT_FOOTER
)

# 5. PAGE SAISIE D'UNE SORTIE
EXIT_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="bg-white p-4 rounded-xl shadow mb-4">
            <h2 class="text-sm font-bold text-amber-700 mb-3">➖ Enregistrer une Sortie (Consommation)</h2>
            <form action="/movement_exit" method="POST" class="space-y-3">
                <div>
                    <label class="block text-xs font-semibold text-gray-600 mb-1">Sélectionner l'article</label>
                    <select name="article_id" required class="w-full p-2.5 border rounded text-sm bg-white font-medium">
                        <option value="">-- Choisir une pièce --</option>
                        {% for item in articles %}
                        <option value="{{ item.id }}">{{ item.name }} (Réf: {{ item.reference or 'N/C' }}) - Stock dispo: {{ item.quantity }} [📍 {{ item.loc_name }}]</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Quantité sortie</label>
                        <input type="number" name="qty" value="1" min="1" required class="w-full p-2 border rounded text-sm text-center font-bold">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Équipement cible</label>
                        <select name="equipment_id" class="w-full p-2 border rounded text-sm bg-white">
                            {% for eq in equipment %}
                            <option value="{{ eq.id }}">{{ eq.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </div>
                <div>
                    <label class="block text-xs font-semibold text-gray-600 mb-1">Motif / Intervention</label>
                    <input type="text" name="reason" placeholder="Ex: Réparation suite panne..." required class="w-full p-2 border rounded text-sm">
                </div>
                <button type="submit" class="w-full bg-amber-600 text-white p-2.5 rounded text-sm font-semibold hover:bg-amber-700">Valider la sortie</button>
            </form>
        </div>
"""
    + LAYOUT_FOOTER
)

# 6. PAGE ÉTAT DES STOCKS
STOCK_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="bg-white p-4 rounded-xl shadow mb-4">
            <div class="flex justify-between items-center mb-2">
                <h2 class="text-sm font-bold text-blue-700">📦 État des Stocks & Filtres</h2>
                <span class="text-xs font-bold text-indigo-700 bg-indigo-50 px-2 py-1 rounded">Valeur : {{ "%.2f"|format(total_stock_value) }} €</span>
            </div>
            <form method="GET" action="/stock" class="space-y-2">
                <input type="text" name="search" value="{{ search_query or '' }}" placeholder="🔍 Rechercher par nom ou référence..." class="w-full p-2 border rounded text-xs bg-gray-50">
                <div class="grid grid-cols-2 gap-2">
                    <select name="loc_filter" class="w-full p-2 border rounded text-xs bg-gray-50">
                        <option value="">Toutes les zones (Lieux)</option>
                        {% for loc in locations %}
                        <option value="{{ loc.id }}" {% if current_loc == loc.id|string %}selected{% endif %}>📍 {{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <select name="eq_filter" class="w-full p-2 border rounded text-xs bg-gray-50">
                        <option value="">Tous les équipements</option>
                        {% for eq in equipment %}
                        <option value="{{ eq.id }}" {% if current_eq == eq.id|string %}selected{% endif %}>⚙️ {{ eq.name }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="flex gap-2 pt-1">
                    <button type="submit" class="flex-1 bg-blue-600 text-white p-2 rounded text-xs font-semibold hover:bg-blue-700">Filtrer</button>
                    {% if search_query or current_loc or current_eq %}
                    <a href="/stock" class="bg-red-100 text-red-700 px-3 py-2 rounded text-xs font-semibold flex items-center justify-center hover:bg-red-200">Effacer</a>
                    {% endif %}
                </div>
            </form>
        </div>

        <div class="space-y-3">
            <h3 class="text-xs font-bold text-gray-500 uppercase tracking-wide">Inventaire ({{ articles|length }} articles)</h3>
            {% for item in articles %}
            <div class="bg-white p-3.5 rounded-xl shadow space-y-2">
                <div class="flex justify-between items-center gap-3">
                    {% if item.image_filename %}
                    <img src="{{ url_for('static', filename='uploads/' + item.image_filename) }}" alt="Photo" class="w-14 h-14 object-cover rounded-lg border flex-shrink-0">
                    {% else %}
                    <div class="w-14 h-14 bg-gray-100 rounded-lg border flex items-center justify-center text-gray-400 text-[9px] text-center flex-shrink-0">Pas de photo</div>
                    {% endif %}
                    <div class="flex-grow">
                        <div class="font-bold text-sm text-gray-800">{{ item.name }}</div>
                        <div class="text-xs text-gray-500 flex gap-2 items-center">
                            <span>Réf: {{ item.reference or 'N/C' }}</span>
                            <span class="font-semibold text-green-700">{{ "%.2f"|format(item.price) }} €/u</span>
                            {% if item.is_estimated_price %}
                            <span class="bg-amber-100 text-amber-800 text-[9px] px-1.5 py-0.5 rounded font-bold">Estimé</span>
                            {% else %}
                            <span class="bg-emerald-100 text-emerald-800 text-[9px] px-1.5 py-0.5 rounded font-bold">Réel</span>
                            {% endif %}
                        </div>
                        <div class="mt-1 flex flex-wrap gap-1">
                            <span class="bg-blue-50 text-blue-700 text-[10px] px-2 py-0.5 rounded font-medium">📍 {{ item.loc_name }}</span>
                            <span class="bg-purple-50 text-purple-700 text-[10px] px-2 py-0.5 rounded font-medium">⚙️ {{ item.eq_name }}</span>
                        </div>
                    </div>
                    <div class="flex items-center gap-2 flex-shrink-0">
                        <form action="/update/{{ item.id }}" method="POST">
                            <input type="hidden" name="action" value="minus">
                            <button type="submit" class="w-7 h-7 bg-gray-100 rounded-full font-bold text-gray-600 flex items-center justify-center hover:bg-gray-200">-</button>
                        </form>
                        <span class="font-bold text-base w-6 text-center {% if item.quantity <= item.min_threshold %}text-red-600{% else %}text-gray-800{% endif %}">
                            {{ item.quantity }}
                        </span>
                        <form action="/update/{{ item.id }}" method="POST">
                            <input type="hidden" name="action" value="plus">
                            <button type="submit" class="w-7 h-7 bg-gray-100 rounded-full font-bold text-gray-600 flex items-center justify-center hover:bg-gray-200">+</button>
                        </form>
                    </div>
                </div>

                <div class="flex gap-2 pt-1 border-t border-gray-100">
                    <a href="/edit/{{ item.id }}" class="flex-1 bg-gray-100 text-gray-700 py-1.5 rounded text-center text-xs font-semibold hover:bg-gray-200">✏️ Modifier</a>
                    <form action="/delete/{{ item.id }}" method="POST" onsubmit="return confirm('Voulez-vous vraiment supprimer cet article ?');" class="flex-1">
                        <button type="submit" class="w-full bg-red-50 text-red-600 py-1.5 rounded text-center text-xs font-semibold hover:bg-red-100">🗑️ Supprimer</button>
                    </form>
                </div>
            </div>
            {% endfor %}
        </div>
"""
    + LAYOUT_FOOTER
)

# 7. PAGE DE MODIFICATION D'UN ARTICLE
EDIT_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="bg-white p-4 rounded-xl shadow mb-4">
            <h2 class="text-sm font-bold text-blue-700 mb-3">✏️ Modifier l'article</h2>
            <form action="/edit/{{ article.id }}" method="POST" enctype="multipart/form-data" class="space-y-3">
                <div class="bg-blue-50 p-3 rounded-lg border border-blue-100 flex items-center gap-3">
                    {% if article.image_filename %}
                    <img src="{{ url_for('static', filename='uploads/' + article.image_filename) }}" class="w-12 h-12 object-cover rounded border">
                    {% endif %}
                    <div class="flex-grow">
                        <label class="block text-[11px] font-semibold text-blue-900 mb-1">Remplacer la photo (Optionnel)</label>
                        <input type="file" name="photo" accept="image/*" capture="environment" class="w-full text-xs text-gray-600">
                    </div>
                </div>
                
                <div>
                    <label class="block text-xs font-semibold text-gray-600 mb-1">Intitulé / Nom de la pièce</label>
                    <input type="text" name="name" value="{{ article.name }}" required class="w-full p-2 border rounded text-sm">
                </div>
                
                <div class="grid grid-cols-3 gap-2">
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Référence</label>
                        <input type="text" name="reference" value="{{ article.reference or '' }}" class="w-full p-2 border rounded text-sm">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Quantité</label>
                        <input type="number" name="quantity" value="{{ article.quantity }}" min="0" required class="w-full p-2 border rounded text-sm">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Prix (€)</label>
                        <input type="number" step="0.01" name="price" value="{{ article.price }}" required class="w-full p-2 border rounded text-sm">
                    </div>
                </div>

                <div class="flex items-center gap-2 bg-gray-50 p-2.5 rounded border">
                    <input type="checkbox" id="is_estimated_price" name="is_estimated_price" value="1" {% if article.is_estimated_price %}checked{% endif %} class="w-4 h-4 text-blue-600 rounded">
                    <label for="is_estimated_price" class="text-xs font-semibold text-gray-700 cursor-pointer">Il s'agit d'un prix estimé</label>
                </div>

                <div class="grid grid-cols-2 gap-2">
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Lieu</label>
                        <select name="location_id" class="w-full p-2 border rounded text-sm bg-white">
                            {% for loc in locations %}
                            <option value="{{ loc.id }}" {% if article.location_id == loc.id %}selected{% endif %}>📍 {{ loc.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Équipement</label>
                        <select name="equipment_id" class="w-full p-2 border rounded text-sm bg-white">
                            {% for eq in equipment %}
                            <option value="{{ eq.id }}" {% if article.equipment_id == eq.id %}selected{% endif %}>⚙️ {{ eq.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </div>

                <div class="flex gap-2 pt-2">
                    <a href="/stock" class="flex-1 bg-gray-200 text-gray-700 p-2.5 rounded text-center text-sm font-semibold hover:bg-gray-300">Annuler</a>
                    <button type="submit" class="flex-1 bg-blue-600 text-white p-2.5 rounded text-sm font-semibold hover:bg-blue-700">Enregistrer</button>
                </div>
            </form>
        </div>
"""
    + LAYOUT_FOOTER
)

# 8. PAGE HISTORIQUE DES MOUVEMENTS
HISTORY_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="space-y-3">
            <h2 class="text-sm font-bold text-purple-800 mb-2">📜 Historique des Mouvements</h2>
            {% for m in movements %}
            <div class="bg-white p-3 rounded-xl shadow border-l-4 {% if m.type == 'ENTREE' %}border-emerald-500{% else %}border-amber-500{% endif %} space-y-1">
                <div class="flex justify-between items-center">
                    <span class="text-xs font-bold {% if m.type == 'ENTREE' %}text-emerald-700{% else %}text-amber-700{% endif %}">
                        {% if m.type == 'ENTREE' %}➕ ENTREE (+{{ m.quantity }}){% else %}➖ SORTIE (-{{ m.quantity }}){% endif %}
                    </span>
                    <span class="text-[10px] text-gray-400">{{ m.date }}</span>
                </div>
                <div class="font-bold text-sm text-gray-800">{{ m.article_name }} <span class="text-xs font-normal text-gray-500">(Réf: {{ m.reference or 'N/C' }})</span></div>
                <div class="text-xs text-gray-600 bg-gray-50 p-1.5 rounded border">
                    <span class="font-semibold">Motif :</span> {{ m.reason or 'Aucun motif' }}
                </div>
            </div>
            {% endfor %}
        </div>
"""
    + LAYOUT_FOOTER
)

# 9. PAGE DE GESTION DES LIEUX ET ÉQUIPEMENTS
SETTINGS_TEMPLATE = (
    LAYOUT_HEADER
    + """
        <div class="space-y-6">
            <h2 class="text-sm font-bold text-gray-800 mb-2">⚙️ Gestion des Lieux & Équipements</h2>

            <div class="bg-white p-4 rounded-xl shadow space-y-3">
                <h3 class="text-xs font-bold text-blue-800 uppercase">📍 Lieux / Zones de stockage</h3>
                <form action="/add_location" method="POST" class="flex gap-2">
                    <input type="text" name="name" placeholder="Nouveau lieu..." required class="flex-grow p-2 border rounded text-xs">
                    <button type="submit" class="bg-blue-600 text-white px-3 py-2 rounded text-xs font-semibold hover:bg-blue-700">Ajouter</button>
                </form>
                <div class="divide-y text-xs">
                    {% for loc in locations %}
                    <div class="py-2 flex justify-between items-center">
                        <span class="font-medium text-gray-800">{{ loc.name }}</span>
                        <form action="/delete_location/{{ loc.id }}" method="POST" onsubmit="return confirm('Supprimer ce lieu ?');">
                            <button type="submit" class="text-red-600 font-semibold hover:underline">Supprimer</button>
                        </form>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="bg-white p-4 rounded-xl shadow space-y-3">
                <h3 class="text-xs font-bold text-purple-800 uppercase">⚙️ Équipements / Machines & Lieu associé</h3>
                <form action="/add_equipment" method="POST" class="space-y-2">
                    <input type="text" name="name" placeholder="Nom de l'équipement..." required class="w-full p-2 border rounded text-xs">
                    <select name="location_id" required class="w-full p-2 border rounded text-xs bg-white">
                        <option value="">-- Choisir le lieu rattaché --</option>
                        {% for loc in locations %}
                        <option value="{{ loc.id }}">📍 {{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="w-full bg-purple-600 text-white py-2 rounded text-xs font-semibold hover:bg-purple-700">Ajouter l'équipement</button>
                </form>
                <div class="divide-y text-xs pt-2">
                    {% for eq in equipment %}
                    <div class="py-2.5 flex justify-between items-center">
                        <div>
                            <span class="font-bold text-gray-800 block">{{ eq.name }}</span>
                            <span class="text-[10px] text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded font-medium">📍 {{ eq.loc_name or 'Aucun lieu' }}</span>
                        </div>
                        <form action="/delete_equipment/{{ eq.id }}" method="POST" onsubmit="return confirm('Supprimer cet équipement ?');">
                            <button type="submit" class="text-red-600 font-semibold hover:underline">Supprimer</button>
                        </form>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
"""
    + LAYOUT_FOOTER
)


# --- ROUTES FLASK ---


def calculate_total_stock_value(articles_list=None):
  db = get_db()
  if articles_list is None:
    articles_list = db.execute(
        "SELECT quantity, price FROM articles"
    ).fetchall()
  return sum((item["quantity"] * item["price"]) for item in articles_list)


@app.route("/")
def home():
  total_val = calculate_total_stock_value()
  return render_template_string(HOME_TEMPLATE, total_stock_value=total_val)


@app.route("/summary")
def summary_view():
  db = get_db()
  total_val = calculate_total_stock_value()

  summary_locations = db.execute("""
        SELECT l.name as location_name, SUM(a.quantity * a.price) as loc_value
        FROM locations l
        LEFT JOIN articles a ON a.location_id = l.id
        GROUP BY l.id, l.name
        ORDER BY loc_value DESC
    """).fetchall()

  summary_equipment = db.execute("""
        SELECT e.name as equipment_name, SUM(a.quantity * a.price) as eq_value
        FROM equipment e
        LEFT JOIN articles a ON a.equipment_id = e.id
        GROUP BY e.id, e.name
        ORDER BY eq_value DESC
    """).fetchall()

  return render_template_string(
      SUMMARY_TEMPLATE,
      total_stock_value=total_val,
      summary_locations=summary_locations,
      summary_equipment=summary_equipment,
  )


@app.route("/detailed_inventory")
def detailed_inventory_view():
  db = get_db()
  total_val = calculate_total_stock_value()
  articles = db.execute("""
        SELECT a.*, l.name as loc_name, e.name as eq_name 
        FROM articles a
        LEFT JOIN locations l ON a.location_id = l.id
        LEFT JOIN equipment e ON a.equipment_id = e.id
        ORDER BY a.name
    """).fetchall()

  return render_template_string(
      DETAILED_INVENTORY_TEMPLATE,
      total_stock_value=total_val,
      articles=articles,
  )


@app.route("/entry")
def entry_form():
  db = get_db()
  locations = db.execute("SELECT * FROM locations").fetchall()
  equipment = db.execute("SELECT * FROM equipment").fetchall()
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
  articles = db.execute("""
        SELECT a.*, l.name as loc_name 
        FROM articles a 
        LEFT JOIN locations l ON a.location_id = l.id 
        ORDER BY a.name
    """).fetchall()
  equipment = db.execute("SELECT * FROM equipment").fetchall()
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
  locations = db.execute("SELECT * FROM locations").fetchall()
  equipment = db.execute("SELECT * FROM equipment").fetchall()

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
    query += " AND (a.name LIKE ? OR a.reference LIKE ?)"
    params.extend([f"%{search_query}%", f"%{search_query}%"])
  if loc_filter:
    query += " AND a.location_id = ?"
    params.append(loc_filter)
  if eq_filter:
    query += " AND a.equipment_id = ?"
    params.append(eq_filter)

  query += " ORDER BY a.name"
  articles = db.execute(query, params).fetchall()

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
        db.execute(
            """
                UPDATE articles SET name = ?, reference = ?, quantity = ?, price = ?, 
                is_estimated_price = ?, location_id = ?, equipment_id = ?, image_filename = ? 
                WHERE id = ?
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
        db.execute(
            """
                UPDATE articles SET name = ?, reference = ?, quantity = ?, price = ?, 
                is_estimated_price = ?, location_id = ?, equipment_id = ? 
                WHERE id = ?
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
    return redirect(url_for("stock_view"))

  article = db.execute("SELECT * FROM articles WHERE id = ?", (id,)).fetchone()
  locations = db.execute("SELECT * FROM locations ORDER BY name").fetchall()
  equipment = db.execute("SELECT * FROM equipment ORDER BY name").fetchall()
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
  db.execute("DELETE FROM articles WHERE id = ?", (id,))
  db.commit()
  return redirect(url_for("stock_view"))


@app.route("/history")
def history_view():
  db = get_db()
  movements = db.execute("""
        SELECT m.*, a.name as article_name, a.reference 
        FROM movements m
        LEFT JOIN articles a ON m.article_id = a.id
        ORDER BY m.date DESC
    """).fetchall()
  total_val = calculate_total_stock_value()
  return render_template_string(
      HISTORY_TEMPLATE, movements=movements, total_stock_value=total_val
  )


@app.route("/settings")
def settings_view():
  db = get_db()
  locations = db.execute("SELECT * FROM locations ORDER BY name").fetchall()
  equipment = db.execute("""
        SELECT e.*, l.name as loc_name 
        FROM equipment e 
        LEFT JOIN locations l ON e.location_id = l.id 
        ORDER BY e.name
    """).fetchall()
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
  name = request.form["name"].strip()
  if name:
    db.execute("INSERT INTO locations (name) VALUES (?)", (name,))
    db.commit()
  return redirect(url_for("settings_view"))


@app.route("/delete_location/<int:id>", methods=["POST"])
def delete_location(id):
  db = get_db()
  db.execute("DELETE FROM locations WHERE id = ?", (id,))
  db.commit()
  return redirect(url_for("settings_view"))


@app.route("/add_equipment", methods=["POST"])
def add_equipment():
  db = get_db()
  name = request.form["name"].strip()
  location_id = request.form["location_id"]
  if name and location_id:
    db.execute(
        "INSERT INTO equipment (name, location_id) VALUES (?, ?)",
        (name, location_id),
    )
    db.commit()
  return redirect(url_for("settings_view"))


@app.route("/delete_equipment/<int:id>", methods=["POST"])
def delete_equipment(id):
  db = get_db()
  db.execute("DELETE FROM equipment WHERE id = ?", (id,))
  db.commit()
  return redirect(url_for("settings_view"))


@app.route("/add", methods=["POST"])
def add_article():
  db = get_db()
  name = request.form["name"]
  reference = request.form["reference"]
  quantity = int(request.form["quantity"])
  price = float(request.form["price"] or 0.0)
  is_estimated_price = 1 if "is_estimated_price" in request.form else 0
  location_id = request.form["location_id"]
  equipment_id = request.form["equipment_id"]
  reason = request.form["reason"] or "Stock initial / Entrée"

  filename = None
  if "photo" in request.files:
    file = request.files["photo"]
    if file and allowed_file(file.filename):
      filename = secure_filename(file.filename)
      filename = f"art_{os.urandom(4).hex()}_{filename}"
      file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

  cursor = db.execute(
      """
        INSERT INTO articles (name, reference, quantity, price, is_estimated_price, location_id, equipment_id, image_filename) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
  article_id = cursor.lastrowid

  db.execute(
      """
        INSERT INTO movements (article_id, type, quantity, reason) 
        VALUES (?, 'ENTREE', ?, ?)
    """,
      (article_id, quantity, reason),
  )
  db.commit()
  return redirect(url_for("stock_view"))


@app.route("/movement_exit", methods=["POST"])
def movement_exit():
  db = get_db()
  article_id = request.form["article_id"]
  qty = int(request.form["qty"])
  reason = request.form["reason"]

  item = db.execute(
      "SELECT quantity FROM articles WHERE id = ?", (article_id,)
  ).fetchone()
  if item:
    current_qty = item["quantity"]
    new_qty = max(0, current_qty - qty)

    db.execute(
        "UPDATE articles SET quantity = ? WHERE id = ?", (new_qty, article_id)
    )
    db.execute(
        """
            INSERT INTO movements (article_id, type, quantity, reason) 
            VALUES (?, ?, ?, ?)
        """,
        (article_id, "SORTIE", qty, reason),
    )
    db.commit()

  return redirect(url_for("stock_view"))


@app.route("/update/<int:id>", methods=["POST"])
def update_quantity(id):
  db = get_db()
  action = request.form["action"]
  item = db.execute("SELECT quantity FROM articles WHERE id = ?", (id,)).fetchone()
  if item:
    current_qty = item["quantity"]
    new_qty = (
        current_qty + 1 if action == "plus" else max(0, current_qty - 1)
    )
    db.execute("UPDATE articles SET quantity = ? WHERE id = ?", (new_qty, id))
    db.commit()
  return redirect(url_for("stock_view"))


if __name__ == "__main__":
  init_db()
  app.run(host="0.0.0.0", port=5000, debug=True)