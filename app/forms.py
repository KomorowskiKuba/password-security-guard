from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, EmailField, IntegerField
from wtforms.validators import InputRequired, Length, Email


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=60)])
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = EmailField('E-mail', validators=[InputRequired(), Email(message='Invalid e-mail!'), Length(min=5, max=30)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=60)])
    password_confirmation = PasswordField('Password confirmation', validators=[InputRequired(), Length(min=8, max=60)])


class PasswordForm(FlaskForm):
    address = StringField('Address', validators=[InputRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=60)])


class PasswordResetForm(FlaskForm):
    email = EmailField('E-mail', validators=[InputRequired(), Email(message='Invalid e-mail!'), Length(min=5, max=30)])


class PasswordAdditionalAuthForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=60)])
