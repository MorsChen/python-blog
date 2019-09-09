from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError, TextField, TextAreaField, validators, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, InputRequired



app = Flask(__name__)

app.secret_key = "Stupid Things"
db = SQLALchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, nullable = False, unique = True)
    email = db.Column(db.String, nullable = False, unique = True)
    password = db.Column(db.String, nullable = False)
    
    def set_pass(self, passw):
        self.password = generate_password_hash(passw)
        
    def check_passw(self, passw):
        return check_password_hash(self.password,passw)
    

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