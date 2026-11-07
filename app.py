import datetime
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
            article_id INTEGER REFERENCES articles(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            supplier TEXT,
            invoice_number TEXT,
            reason TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
  cursor.execute("""
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS min_threshold INTEGER DEFAULT 2;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS supplier TEXT;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS invoice_number TEXT;
        ALTER TABLE articles ADD COLUMN IF NOT EXISTS entry_date DATE;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS supplier TEXT;
        ALTER TABLE movements ADD COLUMN IF NOT EXISTS invoice_number TEXT;
    """)
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion & Suivi de Stock</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            .no-print { display: none !important; }
            body { background: white !important; font-size: 11px; }
            .print-table { border: 1px solid #CBD5E1 !important; }
            .page-break { page-break-before: always; }
        }
        .bg-forest { background-color: #0b3d2c; }
        .bg-forest-light { background-color: #124e38; }
        .border-forest { border-color: #0b3d2c; }
        .text-forest { color: #0b3d2c; }
    </style>
</head>
<body class="bg-slate-50 text-slate-800 font-sans antialiased min-h-screen flex flex-col">

    <!-- Header / Navbar Principal -->
    <header class="bg-forest text-white shadow-md border-b border-emerald-900 no-print">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center gap-3">
                    <div class="w-9 h-9 bg-forest-light rounded-lg flex items-center justify-center font-bold text-emerald-300 border border-emerald-700 shadow-inner">
                        🌿
                    </div>
                    <div>
                        <a href="/" class="text-sm font-extrabold tracking-wider uppercase text-white block">SUIVI INVENTAIRE</a>
                        <span class="text-[10px] text-emerald-300 font-medium tracking-wide">CAPITAL IMMOBILISÉ : {{ "%.2f"|format(total_stock_value or 0) }} €</span>
                    </div>
                </div>

                <nav class="flex space-x-1 sm:space-x-2">
                    <a href="/entry" class="px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center gap-1.5 {% if active_page == 'entry' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>✏️</span> Saisie
                    </a>
                    <a href="/stock" class="px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center gap-1.5 {% if active_page == 'stock' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>📊</span> Suivi & Rapport
                    </a>
                    <a href="/settings" class="px-3.5 py-2 rounded-md text-xs font-semibold transition flex items-center gap-1.5 {% if active_page == 'settings' %}bg-forest-light text-emerald-300 border border-emerald-600 shadow-sm{% else %}text-emerald-100 hover:bg-forest-light hover:text-white{% endif %}">
                        <span>⚙️</span> Réglages
                    </a>
                </nav>
            </div>
        </div>
    </header>

    <main class="flex-grow max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
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
    <div class="max-w-3xl mx-auto space-y-6">
        <div class="bg-white rounded-lg shadow-sm border border-slate-200 p-4 flex justify-between items-center">
            <div>
                <h1 class="text-base font-bold text-slate-900">Saisie des Mouvements</h1>
                <p class="text-xs text-slate-500">Enregistrez de nouvelles entrées ou consommez du matériel pour intervention</p>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div class="bg-forest px-6 py-3 border-b border-emerald-900 flex gap-4">
                <span class="text-xs font-bold text-white uppercase tracking-wider">Formulaire d'enregistrement</span>
            </div>
            
            <div class="p-6 space-y-6">
                <!-- Section Entrée -->
                <div class="space-y-4">
                    <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-600"></span> Entrée en stock / Nouvel Article
                    </h2>
                    
                    <form action="/add" method="POST" enctype="multipart/form-data" class="space-y-4">
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            <div class="sm:col-span-2">
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Nom de l'article *</label>
                                <input type="text" name="name" required placeholder="ex: Disjoncteur 16A" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                            </div>
                            <div>
                                <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                                <input type="text" name="reference" placeholder="ex: REF-8840" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                            </div>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
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
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-emerald-50/40 p-3 rounded border border-emerald-100">
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

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
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
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Photo de l'article</label>
                            <input type="file" name="photo" accept="image/*" class="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-emerald-50 file:text-emerald-900">
                        </div>

                        <button type="submit" class="w-full bg-forest hover:bg-forest-light text-white font-semibold py-2.5 rounded text-xs transition shadow-sm">
                            Valider l'Entrée
                        </button>
                    </form>
                </div>

                <hr class="border-slate-200 my-6">

                <!-- Section Sortie -->
                <div class="space-y-4">
                    <h2 class="text-xs font-bold text-slate-700 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-amber-500"></span> Sortie de stock / Consommation (Date enregistrée automatiquement)
                    </h2>

                    <form action="/movement_exit" method="POST" class="space-y-4">
                        <div>
                            <label class="block text-xs font-semibold text-slate-600 mb-1">Article à prélever *</label>
                            <select name="article_id" required class="w-full text-xs p-2.5 border border-slate-300 rounded bg-white">
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
                            Enregistrer la Sortie (Date automatique)
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
"""
    + LAYOUT_FOOTER
)

# --- 2. PAGE DE SUIVI DES DONNÉES ET INVENTAIRE PAR LIEU ---
STOCK_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="space-y-6">
        <div class="bg-forest text-white rounded-lg p-5 shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border border-emerald-900">
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
            <form method="GET" action="/stock" class="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <input type="text" name="search" value="{{ search_query or '' }}" placeholder="Rechercher désignation..." class="text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
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
                    <button type="submit" class="flex-1 bg-forest text-white text-xs font-semibold py-2 rounded hover:bg-forest-light transition">Filtrer</button>
                    {% if search_query or current_loc or current_eq %}
                    <a href="/stock" class="px-3 py-2 text-xs bg-slate-100 text-slate-600 rounded hover:bg-slate-200 flex items-center">Effacer</a>
                    {% endif %}
                </div>
            </form>
        </div>

        <!-- RESTRUCTURATION : INVENTAIRE GROUPÉ PAR LIEU DE STOCKAGE -->
        {% if grouped_articles %}
            {% for group in grouped_articles %}
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden mb-6">
                <!-- En-tête du Lieu -->
                <div class="bg-forest text-white px-4 py-3 flex justify-between items-center border-b border-emerald-900">
                    <div class="flex items-center gap-2">
                        <span class="text-base text-emerald-300">📍</span>
                        <h2 class="text-sm font-bold tracking-wide uppercase">{{ group.location_name }}</h2>
                        <span class="text-[11px] bg-forest-light text-emerald-200 px-2 py-0.5 rounded-full font-semibold border border-emerald-800">
                            {{ group.items|length }} article(s)
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
                            {% for item in group.items %}
                            <tr class="{% if item.quantity < item.min_threshold %}bg-rose-50/80 hover:bg-rose-100/80{% else %}hover:bg-slate-50/60{% endif %} transition">
                                <td class="p-2.5 font-bold border-r border-slate-200">
                                    {% if item.quantity < item.min_threshold %}
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
                                            <input type="hidden" name="action" value="minus">
                                            <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">-</button>
                                        </form>
                                        <form action="/update/{{ item.id }}" method="POST" class="inline">
                                            <input type="hidden" name="action" value="plus">
                                            <button type="submit" class="w-5 h-5 bg-slate-200 hover:bg-slate-300 rounded font-bold text-slate-700 text-xs">+</button>
                                        </form>
                                        <form action="/delete/{{ item.id }}" method="POST" onsubmit="return confirm('Supprimer cet article ?');" class="inline ml-1">
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
"""
    + LAYOUT_FOOTER
)

# --- EDIT ARTICLE TEMPLATE ---
EDIT_ARTICLE_TEMPLATE = (
    LAYOUT_HEADER
    + """
    <div class="max-w-2xl mx-auto space-y-6">
        <div class="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-4">
            <div class="flex justify-between items-center pb-3 border-b border-slate-200">
                <h1 class="text-base font-bold text-slate-900">✏️ Modifier l'Article</h1>
                <a href="/stock" class="text-xs text-emerald-800 hover:underline font-semibold">← Retour au tableau</a>
            </div>

            <form action="/edit/{{ article.id }}" method="POST" enctype="multipart/form-data" class="space-y-4">
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div class="sm:col-span-2">
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Désignation / Nom *</label>
                        <input type="text" name="name" value="{{ article.name }}" required class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-slate-600 mb-1">Référence</label>
                        <input type="text" name="reference" value="{{ article.reference or '' }}" class="w-full text-xs p-2.5 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-4 gap-4">
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

                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-emerald-50/40 p-3 rounded border border-emerald-100">
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

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
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

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- Emplacements -->
            <div class="bg-white rounded-lg border border-slate-200 shadow-sm p-5 space-y-4">
                <h2 class="text-xs font-bold text-slate-800 uppercase tracking-wider pb-2 border-b border-slate-200 flex items-center gap-2">
                    📍 Emplacements de Stockage
                </h2>
                <form action="/add_location" method="POST" class="flex gap-2">
                    <input type="text" name="name" required placeholder="Nouveau lieu..." class="flex-grow text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    <button type="submit" class="bg-forest hover:bg-forest-light text-white px-3 py-2 rounded text-xs font-semibold transition">Ajouter</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for loc in locations %}
                    <div class="py-2.5 flex justify-between items-center">
                        <form action="/edit_location/{{ loc.id }}" method="POST" class="flex items-center gap-2 flex-grow mr-2">
                            <input type="text" name="name" value="{{ loc.name }}" required class="text-xs p-1 border border-transparent hover:border-slate-300 focus:border-emerald-700 rounded flex-grow font-semibold text-slate-700">
                            <button type="submit" class="text-emerald-800 hover:underline text-[11px] font-medium">Sauvegarder</button>
                        </form>
                        <form action="/delete_location/{{ loc.id }}" method="POST" onsubmit="return confirm('Supprimer ce lieu ?');">
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
                    <input type="text" name="name" required placeholder="Nom de l'équipement..." class="w-full text-xs p-2 border border-slate-300 rounded outline-none focus:border-emerald-700">
                    <select name="location_id" class="w-full text-xs p-2 border border-slate-300 rounded bg-white">
                        <option value="">-- Rattacher à un emplacement --</option>
                        {% for loc in locations %}
                        <option value="{{ loc.id }}">{{ loc.name }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="w-full bg-forest hover:bg-forest-light text-white py-2 rounded text-xs font-semibold transition">Ajouter l'Équipement</button>
                </form>

                <div class="divide-y divide-slate-100 text-xs pt-2">
                    {% for eq in equipment %}
                    <div class="py-3 space-y-1">
                        <form action="/edit_equipment/{{ eq.id }}" method="POST" class="space-y-1.5">
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
                        <form id="del_eq_{{ eq.id }}" action="/delete_equipment/{{ eq.id }}" method="POST" onsubmit="return confirm('Supprimer cet équipement ?');"></form>
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


# --- ROUTES FLASK ---


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
  today_str = datetime.date.today().strftime("%Y-%m-%d")
  return render_template_string(
      ENTRY_TEMPLATE,
      active_page="entry",
      locations=locations,
      equipment=equipment,
      articles=articles,
      total_stock_value=total_val,
      today_date=today_str,
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
        SELECT a.*, COALESCE(l.name, 'Non assigné') as loc_name, e.name as eq_name 
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

  query += " ORDER BY loc_name ASC, a.name ASC"
  cur.execute(query, params)
  articles = cur.fetchall()
  cur.close()

  filtered_total_val = calculate_total_stock_value(articles)

  # Groupement dynamique par lieu de stockage
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
          "items": data["items"],
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
      current_loc=loc_filter,
      current_eq=eq_filter,
      total_stock_value=filtered_total_val,
  )


@app.route("/edit/<int:id>", methods=["GET", "POST"])
def edit_article(id):
  db = get_db()
  cur = db.cursor()

  if request.method == "POST":
    name = request.form["name"].strip()
    reference = request.form.get("reference")
    quantity = int(request.form.get("quantity", 0))
    min_threshold = int(request.form.get("min_threshold", 2))
    price = float(request.form.get("price") or 0.0)
    is_estimated_price = 1 if "is_estimated_price" in request.form else 0
    supplier = request.form.get("supplier")
    invoice_number = request.form.get("invoice_number")
    entry_date = request.form.get("entry_date") or None
    location_id = request.form.get("location_id") or None
    equipment_id = request.form.get("equipment_id") or None

    if "photo" in request.files and request.files["photo"].filename != "":
      file = request.files["photo"]
      if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"art_{os.urandom(4).hex()}_{filename}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        cur.execute(
            """
                UPDATE articles SET name=%s, reference=%s, quantity=%s, min_threshold=%s, price=%s, 
                is_estimated_price=%s, supplier=%s, invoice_number=%s, entry_date=%s, location_id=%s, equipment_id=%s, image_filename=%s
                WHERE id=%s
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
                id,
            ),
        )
    else:
      cur.execute(
          """
            UPDATE articles SET name=%s, reference=%s, quantity=%s, min_threshold=%s, price=%s, 
            is_estimated_price=%s, supplier=%s, invoice_number=%s, entry_date=%s, location_id=%s, equipment_id=%s
            WHERE id=%s
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
      EDIT_ARTICLE_TEMPLATE,
      active_page="stock",
      article=article,
      locations=locations,
      equipment=equipment,
      total_stock_value=total_val,
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


@app.route("/edit_location/<int:id>", methods=["POST"])
def edit_location(id):
  db = get_db()
  cur = db.cursor()
  name = request.form["name"].strip()
  if name:
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


@app.route("/edit_equipment/<int:id>", methods=["POST"])
def edit_equipment(id):
  db = get_db()
  cur = db.cursor()
  name = request.form["name"].strip()
  location_id = request.form.get("location_id") or None
  if name:
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
  name = request.form["name"]
  reference = request.form.get("reference")
  quantity = int(request.form.get("quantity", 1))
  min_threshold = int(request.form.get("min_threshold", 2))
  price = float(request.form.get("price") or 0.0)
  is_estimated_price = 1 if "is_estimated_price" in request.form else 0
  supplier = request.form.get("supplier")
  invoice_number = request.form.get("invoice_number")
  entry_date = request.form.get("entry_date") or datetime.date.today()
  location_id = request.form.get("location_id") or None
  equipment_id = request.form.get("equipment_id") or None
  reason = f"Entrée - Fournisseur: {supplier or 'N/C'} | Facture: {invoice_number or 'N/C'}"

  filename = None
  if "photo" in request.files:
    file = request.files["photo"]
    if file and allowed_file(file.filename):
      filename = secure_filename(file.filename)
      filename = f"art_{os.urandom(4).hex()}_{filename}"
      file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

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
        INSERT INTO movements (article_id, type, quantity, supplier, invoice_number, reason, date) 
        VALUES (%s, 'ENTREE', %s, %s, %s, %s, CURRENT_TIMESTAMP)
    """,
      (article_id, quantity, supplier, invoice_number, reason),
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
            INSERT INTO movements (article_id, type, quantity, reason, date) 
            VALUES (%s, 'SORTIE', %s, %s, CURRENT_TIMESTAMP)
        """,
        (article_id, qty, reason),
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
