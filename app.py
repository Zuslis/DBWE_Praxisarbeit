# ---------------------------------------
# Flask Webanwendung mit Datenbank & RESTful API
# Kompletter Code inkl. Kommentare auf Deutsch
# ---------------------------------------

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os

# ---------------------------------------
# Flask-App Initialisierung & Konfiguration
# ---------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Geheimschlüssel für Sessions und Token

# ---------------------------------------
# Flexible Datenbank Konfiguration: MySQL wenn möglich, sonst SQLite
# ---------------------------------------

MYSQL_USER = os.getenv('MYSQL_USER', 'praxisuser')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'Moo5fie!Phahmia@JohGheitai')
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_DB = os.getenv('MYSQL_DB', 'praxisapp_db')

try:
    import pymysql
    from sqlalchemy import create_engine

    mysql_uri = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}'
    engine = create_engine(mysql_uri)

    # Teste Verbindung
    engine.connect().close()

    app.config['SQLALCHEMY_DATABASE_URI'] = mysql_uri
    print("✅ MySQL-Verbindung erfolgreich! Verwende MySQL-Datenbank.")

except Exception as e:
    # Fallback auf SQLite
    sqlite_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'app.db')
    sqlite_uri = f'sqlite:///{sqlite_path}'

    app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_uri
    print(f"⚠️  MySQL nicht erreichbar! Verwende SQLite. Grund: {e}")

# ---------------------------------------
# Weitere Konfiguration
# ---------------------------------------
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Abschalten unnötiger Warnungen

# ---------------------------------------
# Initialisierung der Extensions
# ---------------------------------------

db = SQLAlchemy(app)          # ORM zur Datenbank-Verwaltung
bcrypt = Bcrypt(app)          # Passwort-Hashing
login_manager = LoginManager(app)  # User-Session-Handling
login_manager.login_view = 'login' # Standard-Login-Route
ma = Marshmallow(app)         # Serialisierung für API
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # Erzeugt sichere Tokens (z.B. Passwort-Reset)

# ---------------------------------------
# Datenbank-Modelle
# ---------------------------------------

# Benutzer-Tabelle
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    projects = db.relationship('Project', backref='owner', lazy=True)  # Beziehung zu Projekten

# Projekt-Tabelle
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ---------------------------------------
# Marshmallow-Schemas für API
# ---------------------------------------

class ProjectSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Project
        sqla_session = db.session  # wichtig, damit Marshmallow weiß, welche Session verwendet wird

# Initialisierung der Schemata für einzelne und mehrere Projekte
project_schema = ProjectSchema()
projects_schema = ProjectSchema(many=True)

# ---------------------------------------
# Benutzer-Loader für Flask-Login
# ---------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------------
# Routing der Webanwendung
# ---------------------------------------

# Startseite (leitet auf das Dashboard weiter)
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

# Registrierung neuer Benutzer
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        # Prüfen, ob Username oder Email bereits existieren
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Benutzername oder E-Mail existiert bereits!', 'danger')
            return redirect(url_for('register'))
        
        # Neuen User anlegen
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Registrierung erfolgreich. Bitte einloggen.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Benutzer-Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session.pop('_flashes', None)  # Vorherige Flash-Meldungen löschen
            flash('Erfolgreich eingeloggt.', 'success')
            return redirect(url_for('dashboard'))

        flash('Ungültige E-Mail oder Passwort!', 'danger')
    return render_template('login.html')

# Benutzer-Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Erfolgreich ausgeloggt.', 'info')
    return redirect(url_for('login'))

# Dashboard (Projekte anzeigen)
@app.route('/dashboard')
@login_required
def dashboard():
    # Zeigt nur Projekte des eingeloggten Users an
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects, user=current_user)

# Projekt hinzufügen
@app.route('/add_project', methods=['POST'])
@login_required
def add_project():
    name = request.form['name']
    description = request.form['description']
    project = Project(name=name, description=description, user_id=current_user.id)
    db.session.add(project)
    db.session.commit()
    flash('Projekt erfolgreich hinzugefügt!', 'success')
    return redirect(url_for('dashboard'))

# Projekt löschen
@app.route('/delete_project/<int:id>', methods=['POST'])
@login_required
def delete_project(id):
    project = Project.query.get_or_404(id)
    # Sicherstellen, dass der aktuelle User der Besitzer ist
    if project.owner != current_user:
        flash('Nicht berechtigt, dieses Projekt zu löschen.', 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(project)
    db.session.commit()
    flash('Projekt gelöscht!', 'success')
    return redirect(url_for('dashboard'))

# Projekt bearbeiten
@app.route('/edit_project/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_project(id):
    # Hole das Projekt anhand der ID, gib 404 zurück, wenn es nicht existiert
    project = Project.query.get_or_404(id)

    # Prüfe, ob das aktuelle Projekt dem eingeloggten User gehört
    if project.owner != current_user:
        flash('Nicht berechtigt, dieses Projekt zu bearbeiten.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Hole die neuen Werte aus dem Formular
        project.name = request.form['name']
        project.description = request.form['description']

        # Speichere die Änderungen in der Datenbank
        db.session.commit()

        flash('Projekt wurde erfolgreich aktualisiert.', 'success')
        return redirect(url_for('dashboard'))

    # Wenn es sich um einen GET-Request handelt, zeige das Bearbeitungsformular
    return render_template('edit_project.html', project=project)

# ---------------------------------------
# RESTful API Endpunkte
# ---------------------------------------

# Alle Projekte des aktuellen Users als JSON
@app.route('/api/projects', methods=['GET'])
@login_required
def api_get_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return projects_schema.jsonify(projects)

# Ein einzelnes Projekt anzeigen
@app.route('/api/projects/<int:id>', methods=['GET'])
@login_required
def api_get_project(id):
    project = Project.query.get_or_404(id)
    if project.owner != current_user:
        return jsonify({'error': 'Nicht berechtigt'}), 403
    return project_schema.jsonify(project)

# Neues Projekt per API erstellen
@app.route('/api/projects', methods=['POST'])
@login_required
def api_create_project():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    project = Project(name=name, description=description, user_id=current_user.id)
    db.session.add(project)
    db.session.commit()
    return project_schema.jsonify(project), 201

# Projekt per API aktualisieren
@app.route('/api/projects/<int:id>', methods=['PUT'])
@login_required
def api_update_project(id):
    project = Project.query.get_or_404(id)
    if project.owner != current_user:
        return jsonify({'error': 'Nicht berechtigt'}), 403
    data = request.get_json()
    project.name = data.get('name', project.name)
    project.description = data.get('description', project.description)
    db.session.commit()
    return project_schema.jsonify(project)

# Projekt per API löschen
@app.route('/api/projects/<int:id>', methods=['DELETE'])
@login_required
def api_delete_project(id):
    project = Project.query.get_or_404(id)
    if project.owner != current_user:
        return jsonify({'error': 'Nicht berechtigt'}), 403
    db.session.delete(project)
    db.session.commit()
    return jsonify({'message': 'Projekt gelöscht'})

# ---------------------------------------
# Passwort-Zurücksetzen anfordern
# ---------------------------------------

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            flash(f'Passwort-Reset-Link (Simulation): {url_for("reset_password", token=token, _external=True)}', 'info')
        else:
            flash('E-Mail wurde nicht gefunden.', 'danger')
    return render_template('reset_password_request.html')

# Passwort-Zurücksetzen über Token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('Der Reset-Link ist abgelaufen.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first_or_404()
        new_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user.password = new_password
        db.session.commit()
        flash('Passwort wurde zurückgesetzt. Bitte einloggen.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# ---------------------------------------
# Anwendung starten
# ---------------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Erstellt alle Tabellen, falls noch nicht vorhanden
    app.run(debug=True)  # Startet den Flask-Entwicklungsserver
