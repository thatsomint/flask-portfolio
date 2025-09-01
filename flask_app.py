from datetime import datetime
from flask import Flask, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, LoginManager, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # Added this import
from werkzeug.security import check_password_hash, generate_password_hash
import os
import base64
import hashlib

app = Flask(__name__)
app.config["DEBUG"] = True
app.secret_key = os.environ.get('SECRET_KEY') or "your-very-secret-key-here"  # Improved secret key
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Now this will work

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(256), unique=True)  # Added unique constraint
    password_hash = db.Column(db.String(256))

    def get_id(self):
        return str(self.username)  # Required by Flask-Login

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)  # Added this method

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))
    posted = db.Column(db.DateTime, default=datetime.now)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    commenter = db.relationship('User', foreign_keys=commenter_id)

@login_manager.user_loader
@login_manager.user_loader
def load_user(user_id):
    # Changed to only use username since get_id() returns username
    return User.query.filter_by(username=user_id).first()

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(username="admin")
            admin.set_password("secret")
            db.session.add(admin)
            db.session.commit()

@app.route('/')
def home():
    return redirect(url_for('portfolio'))

@app.route("/portfolio")
def portfolio():
    return render_template('portfolio.html', comments=Comment.query.all())

@app.route("/scratchpad")
def scratchpad():
    return render_template("main_page.html",
                         comments=Comment.query.all(),
                         current_user=current_user)

@app.route("/add_comment", methods=["POST"])
@login_required
def add_comment():
    comment = Comment(
        content=request.form["contents"],
        commenter=current_user
    )
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('scratchpad'))

@app.route("/check_login")
def check_login():
    return f"Currently logged in as: {current_user.username if current_user.is_authenticated else 'Not logged in'}"

@app.route("/login/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('scratchpad'))

    if request.method == "GET":
        return render_template("login_page.html", error=False)

    username = request.form.get("username")
    password = request.form.get("password")

    print(f"Login attempt for: {username}")  # Debug

    user = User.query.filter_by(username=username).first()

    if not user:
        print("User not found!")  # Debug
        return render_template("login_page.html", error=True)

    print(f"Found user: {user.username}")  # Debug
    print(f"Password check result: {user.check_password(password)}")  # Debug

    if not user.check_password(password):
        print("Password check failed!")  # Debug
        print(f"Input password: {password}")  # Debug
        print(f"Stored hash: {user.password_hash}")  # Debug
        return render_template("login_page.html", error=True)

    login_user(user)
    print("Login successful!")  # Debug
    return redirect(url_for('scratchpad'))

@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run()
