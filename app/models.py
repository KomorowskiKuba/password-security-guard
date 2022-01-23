from flask_login import UserMixin
from extensions import db


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