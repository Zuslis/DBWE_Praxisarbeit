# Flask Web Application with Database and RESTful API

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_marshmallow import Marshmallow
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Use MySQL/MariaDB/PostgreSQL in production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
ma = Marshmallow(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)

# Marshmallow Schemas
class ProjectSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Project

project_schema = ProjectSchema()
projects_schema = ProjectSchema(many=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists!')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password!')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    projects = Project.query.all()
    return render_template('dashboard.html', projects=projects, user=current_user)

@app.route('/add_project', methods=['POST'])
@login_required
def add_project():
    name = request.form['name']
    description = request.form['description']
    project = Project(name=name, description=description)
    db.session.add(project)
    db.session.commit()
    flash('Project added successfully!')
    return redirect(url_for('dashboard'))

@app.route('/delete_project/<int:id>', methods=['POST'])
@login_required
def delete_project(id):
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!')
    return redirect(url_for('dashboard'))

# RESTful API Endpoints
@app.route('/api/projects', methods=['GET'])
@login_required
def api_get_projects():
    projects = Project.query.all()
    return projects_schema.jsonify(projects)

@app.route('/api/projects/<int:id>', methods=['GET'])
@login_required
def api_get_project(id):
    project = Project.query.get_or_404(id)
    return project_schema.jsonify(project)

@app.route('/api/projects', methods=['POST'])
@login_required
def api_create_project():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    project = Project(name=name, description=description)
    db.session.add(project)
    db.session.commit()
    return project_schema.jsonify(project), 201

@app.route('/api/projects/<int:id>', methods=['PUT'])
@login_required
def api_update_project(id):
    project = Project.query.get_or_404(id)
    data = request.get_json()
    project.name = data.get('name', project.name)
    project.description = data.get('description', project.description)
    db.session.commit()
    return project_schema.jsonify(project)

@app.route('/api/projects/<int:id>', methods=['DELETE'])
@login_required
def api_delete_project(id):
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    return jsonify({'message': 'Project deleted'})

# Password Reset (Extra Feature)
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            # In a real app, send the email here
            flash(f'Reset link (simulate email): {url_for("reset_password", token=token, _external=True)}')
        else:
            flash('Email not found!')
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The reset link is expired!')
        return redirect(url_for('login'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first_or_404()
        new_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user.password = new_password
        db.session.commit()
        flash('Password has been reset! Please login.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
