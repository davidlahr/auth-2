import os

from flask import Flask, render_template, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from datetime import date
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_auth2.db'

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL1', 'sqlite:///users_auth2.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

TODAY = date.today()

########### CREATE DATABASE #########################

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(100))
# db.create_all()

# ADD ACCOUNT ######################################
# new_account = User(
#     id=1,
#     username='davidl',
#     password='123456')
# db.session.add(new_account)
# db.session.commit()

# WEB FRAMEWORK##############################################

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username1 = request.form.get('username')
        password = request.form.get('password')
        userz = User.query.filter_by(username=username1).first()

        # if password == user.password:
        if check_password_hash(userz.password, password):
            login_user(userz)
            return render_template("secret.html", today=TODAY)

    return render_template("login.html")

@app.route('/main')
def main():
    return render_template('secret.html', today=TODAY)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template('index.html')


@app.route('/new', methods=["GET", "POST"])
def new():
    if request.method == "POST":
        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
            )
        new_account = User(
            username=request.form.get('username'),
            password=hash_and_salted_password
        )
        db.session.add(new_account)
        db.session.commit()
        return render_template("secret.html", user=new_account)
    else:
        return render_template("new.html")


@app.route("/acctlist")
@login_required
def acctlist():
    all_users = db.session.query(User).all()
    return render_template('list.html', user=all_users)

if __name__ == "__main__":
    app.run(debug=True)