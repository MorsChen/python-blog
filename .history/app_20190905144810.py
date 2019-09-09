from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_login import loginManager, login_required, login_user, logout_user

from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextField, TextAreaField, validators, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired

app = Flask(__name__)
login = LoginManager(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///largeblogdb.db'
app.secret_key = "Stupid Things"
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
db = SQLAlchemy(app)
migrate = Migrate(app, db)

POSTGRES = {
       'user': "mors",
       'pw': "1234",
       'db': "blog",
       'host': "localhost",
       'port': 5432,
   }
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
   %(port)s/%(db)s' % POSTGRES


class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, nullable = False, unique = True)
    email = db.Column(db.String, nullable = False, unique = True)
    password = db.Column(db.String, nullable = False)
    
    def set_pass(self, passw):
        self.password = generate_password_hash(passw)
        
    def check_passw(self, passw):
        return check_password_hash(self.password,passw)
    
db.create_all()

class Register(FlaskForm):
    username = StringField("User Name", validators = [DataRequired('Please input your username'), 
        Length(min = 3, max = 20, message = 'username must have at least 3 chars and max 20 chars')])
    email = StringField("Email Address", validators = [DataRequired('Please input an appropiate email address')])
    password = StringField("Password", validators = [DataRequired(), EqualTo('confirm')])
    confirm = StringField("Confirm", validators = [DataRequired()])
    submit = StringField("Register")

    def validators():
        
    
    
    

@app.route('/')
def main():
    return "Hello World !"

if __name__ == "__main__":
    app.run(debug = True)