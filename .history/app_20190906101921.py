from flask import Flask, request, render_template
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
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String, nullable = False)
    body = db.Column(db.String, nullable = False)
    author = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, nullable = False)
    updated = db.Column(db.DateTime)
    
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
        
class Login(FlaskForm):
    email = StringField("Email Address", validators = [DataRequired('Please input an appropiate email address')])
    password = StringField("Password", validators = [DataRequired()])
    submit = SubmitField("Login")
    
class NewPost(FlaskForm):
    title = StringField("Blog Title", validators = [DataRequired('Please input blog title'), 
        Length(min = 3, max = 255, message = 'title must have at least 3 chars and max 255 chars')])
    body = StringField("Blog Body", validators = [DataRequired('Please input blog body'), 
        Length(min = 3, max = 1000, message = 'username must have at least 3 chars and max 1000 chars')])
    submit = SubmitField('Post')
    
@app.route('/register', methods = ['POST', 'GET'])
def register():
    form = Register()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_user = Users(username = form.username.data,
                             email = form.username.data,)
            newu_user.set_pass(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            

@app.route('/login')
def login():
    pass

@app.route('/profile')
def profile():
    pass

@app.route('/logout')
def logout():
    pass
    
@app.route('/newpost')
def newpost():
    pass

@app.route('/editpost')
def editpost():
    pass
    
    

@app.route('/')
def main():
    return render_template('home.html')

if __name__ == "__main__":
    app.run(debug = True)