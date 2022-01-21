import sqlite3
import time
import bleach
import flask_login
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from forms import LoginForm, RegisterForm, PasswordForm
from utils.password_validator import PasswordValidator
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

app.config['SECRET_KEY'] = 'notverysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////guard/app/data/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Bootstrap(app)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)


@app.before_first_request
def create_tables():
    db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

conn = sqlite3.connect('app/data/database.db')


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
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()

    if form.validate_on_submit():
        time.sleep(1)  # TODO: CHANGE TO 5

        user = User.query.filter_by(
            username=bleach.clean(form.username.data)).first()

        if user:
            if check_password_hash(user.master_password, form.password.data):
                login_user(user, remember=form.remember.data)

                return redirect(url_for('home'))

        error = 'Invalid username or password!'

    return render_template('login.html', form=form, error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            error = 'User with this email already exists!'

        else:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256:100000', salt_length=32)

            validation_outcome = PasswordValidator.validate(form.password.data)

            if len(validation_outcome) == 0:
                new_user = User(
                    username=bleach.clean(form.username.data),
                    email=bleach.clean(form.email.data),
                    master_password=hashed_password
                )

                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('login'))

            error = '\n'.join(validation_outcome)

    return render_template('register.html', form=form, error=error)


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    form = PasswordForm()

    passwords = PagePassword.query.filter_by(user_id=flask_login.current_user.id)

    if form.validate_on_submit():
        new_page_password = PagePassword(
            address=bleach.clean(form.address.data),
            password=bleach.clean(form.password.data),
            user_id=flask_login.current_user.id
        )

        db.session.add(new_page_password)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('home.html', form=form, passwords=passwords)


@app.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect(url_for('login'))


#{{ url_for('password_details', id=password.id) }}
@app.route('/home/<id>')
@login_required
def password_details(id):
    return '<p> id </p>'


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
