import time
import json
import flask
import bleach
import sqlite3
import logging
import flask_login

from extensions import db
from models import User, PagePassword
from utils.password_encrypter import PasswordEncrypter
from utils.password_validator import PasswordValidator
from forms import LoginForm, RegisterForm, PasswordForm, PasswordResetForm, PasswordAdditionalAuthForm, PasswordEditForm

from base64 import b64decode
from flask_bootstrap import Bootstrap
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_pyfile('settings.py')

Bootstrap(app)

db.init_app(app)

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

conn = sqlite3.connect('/app/data/database.db')


@app.before_first_request
def create_tables():
    db.create_all()


@app.before_first_request
def read_secrets():
    f = open('secrets.json')
    json_data = json.load(f)

    global PASSWORD_KEY
    global PASSWORD_IV

    PASSWORD_KEY = b64decode(json_data['password_key'])
    PASSWORD_IV = b64decode(json_data['password_iv'])


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
        time.sleep(3)

        user = User.query.filter_by(
            username=bleach.clean(form.username.data)).first()

        if user:
            if check_password_hash(user.master_password, bleach.clean(form.password.data)):
                login_user(user, remember=form.remember.data)

                return redirect(url_for('home'))

        error = 'Invalid username or password!'

    return render_template('login.html', form=form, error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    form = RegisterForm()

    if form.validate_on_submit():
        if User.query.filter_by(email=bleach.clean(form.email.data)).first():
            error = 'User with this email already exists!'

        else:
            if form.password.data == form.password_confirmation.data:
                hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256:100000',
                                                         salt_length=32)

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

            else:
                error = 'Passwords are not the same!'

    return render_template('register.html', form=form, error=error)


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    form = PasswordForm()

    passwords = PagePassword.query.filter_by(user_id=flask_login.current_user.id)

    if form.validate_on_submit():
        new_page_password = PagePassword(
            address=bleach.clean(form.address.data),
            password=PasswordEncrypter.encrypt(
                bleach.clean(form.password.data).encode(),
                PASSWORD_KEY,
                PASSWORD_IV
            ),
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


@app.route('/password-reset', methods=['GET', 'POST'])
def password_reset():
    error = None

    form = PasswordResetForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=bleach.clean(form.email.data)).first()
        if user:
            app.logger.info('Normally we would send email to address: {}'.format(form.email.data))

            return redirect(url_for('login'))
        else:
            error = 'User with provided email does not exist!'

    return render_template('password-reset.html', form=form, error=error)


@app.route('/home/<id>', methods=['GET', 'POST'])
@login_required
def password_details(id):
    error = None

    form = PasswordAdditionalAuthForm()
    password_form = PasswordEditForm()

    if form.validate_on_submit():
        current_user_id = flask_login.current_user.id
        current_user = User.query.filter_by(id=current_user_id).first()

        if current_user:
            if check_password_hash(current_user.master_password, bleach.clean(form.password.data)):
                current_password = PagePassword.query.filter_by(user_id=current_user_id, id=id).first()

                if current_password is None:
                    return redirect(url_for('home'))

                decoded_current_password = PasswordEncrypter.decrypt(
                    current_password.password,
                    PASSWORD_KEY,
                    PASSWORD_IV
                ).decode()

                password_form.address.data = current_password.address
                password_form.password.data = decoded_current_password

                return render_template('password-details.html', id=id, form=password_form)
        else:
            error = 'Invalid password!'

    if password_form.validate_on_submit():
        current_user_id = flask_login.current_user.id
        current_user = User.query.filter_by(id=current_user_id).first()

        if current_user:
            if flask.request.form['btn_identifier'] == 'edit_button':
                current_password = PagePassword.query.filter_by(user_id=current_user_id, id=id).first()

                current_password.address = bleach.clean(password_form.address.data)
                current_password.password = PasswordEncrypter.encrypt(
                    bleach.clean(password_form.password.data).encode(),
                    PASSWORD_KEY,
                    PASSWORD_IV
                )

                db.session.commit()

            if flask.request.form['btn_identifier'] == 'delete_button':
                current_password = PagePassword.query.filter_by(user_id=current_user_id, id=id).first()

                db.session.delete(current_password)
                db.session.commit()

        return redirect(url_for('home'))

    return render_template('password-additional-auth.html', form=form, id=id, error=error)


if __name__ == '__main__':
    app.run(host='0.0.0.0')
else:
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
