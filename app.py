from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, EmailField
from wtforms.validators import InputRequired, Email, Length

app = Flask(__name__)
app.config['SECRET_KEY'] = 'notverysecretkey'
Bootstrap(app)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=60)])
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = EmailField('E-mail', validators=[InputRequired(), Email(message='Invalid e-mail!'), Length(min=5, max=30)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=60)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        return '<h1> Hello ' + form.username.data + ' </h1>'

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        return '<h1> You registered as' + form.username.data + ' </h1>'

    return render_template('register.html', form=form)


@app.route('/home')
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
