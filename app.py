import sqlite3

import flask_login
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegisterForm, PasswordForm

app = Flask(__name__)

app.config['SECRET_KEY'] = 'notverysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/data/database.db'

Bootstrap(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

conn = sqlite3.connect('/app/data/database.db')


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(30), unique=True)
    master_password = db.Column(db.String(60))
    page_password = db.relationship('PagePassword')


class PagePassword(db.Model):
    __tablename__ = 'pagepassword'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100))
    password = db.Column(db.String(60))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.master_password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('home'))
        return '<h1> Invalid username or password! </h1>'

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256', salt_length=32)
        new_user = User(username=form.username.data, email=form.email.data, master_password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return '<h1> You registered as' + form.username.data + ' </h1>'

    return render_template('register.html', form=form)


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    form = PasswordForm()

    print(type(flask_login))
    print('Current user id', flask_login.current_user.id)

    passwords = PagePassword.query.filter_by(user_id=flask_login.current_user.id)

    if form.validate_on_submit():
        new_pagepassword = PagePassword(address=form.address.data, password=form.password.data,
                                        user_id=flask_login.current_user.id)
        db.session.add(new_pagepassword)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('home.html', form=form, passwords=passwords)


@app.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
