from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextField, TextAreaField, validators, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired

app = Flask(__name__)
login = LoginManager(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///largeblogdb.db'
POSTGRES = {
       'user': "mors",
       'pw': "1234",
       'db': "blog",
       'host': "localhost",
       'port': 5432,
   }
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
   %(port)s/%(db)s' % POSTGRES
app.secret_key = "Stupid Things"
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, nullable = False, unique = True)
    email = db.Column(db.String, nullable = False, unique = True)
    password = db.Column(db.String, nullable = False)
    
    def set_pass(self, passw):
        self.password = generate_password_hash(passw)
        
    def check_passw(self, passw):
        return check_password_hash(self.password,passw)
    
class Posts(db.Model):
    id: db.Column(db.Integer, primary_key = True)
    title: db.Column(db.String, nullable = False)
    body: db.Column(db.String, nullable = False)
    author: db.Column(db.Integer, db.ForeignKey('users_id'))
    created: db.Column(db.Datetime, nullable = False)
    updated: db.Column(db.Datetime)
    
db.create_all()

@login.user_loader
def load_user(id):
      return Users.query.get(int(id))

class Register(FlaskForm):
    username = StringField("User Name", validators = [DataRequired('Please input your username'), 
        Length(min = 3, max = 20, message = 'username must have at least 3 chars and max 20 chars')])
    email = StringField("Email Address", validators = [DataRequired('Please input an appropiate email address')])
    password = StringField("Password", validators = [DataRequired(), EqualTo('confirm')])
    confirm = StringField("Confirm", validators = [DataRequired()])
    submit = StringField("Register")

    def validate_username(self, field):
        if Users.query.filter_by(username = field.date).first() :
            raise ValidationError("Your name has been register !!!")
        
    def validate_email(self, field):
        if Users.query.filter_by(email = field.date).first() :
            raise ValidationError("Your email has been register !!!")
        
    
        
        
    
    

@app.route('/')
def main():
    return "Hello World !"

if __name__ == "__main__":
    app.run(debug = True)