from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin, current_user
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
    posts = db.relationship('Posts', backref = 'users', lazy = 'dynamic')
    comments = db.relationship('Comments', backref = 'users', lazy = 'dynamic')
    def set_pass(self, passw):
        self.password = generate_password_hash(passw)
        
    def check_pass(self, passw):
        return check_password_hash(self.password,passw)
    
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String, nullable = False)
    body = db.Column(db.String, nullable = False)
    author = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    created = db.Column(db.DateTime, nullable = False)
    updated = db.Column(db.DateTime)
    comments = db.relationship('Comments', backref='posts', lazy = 'dynamic')
    
class Comments(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String, nullable = False)
    author = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    created = db.Column(db.DateTime, nullable = False)
    updated = db.Column(db.DateTime)
    post = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable = False)
    
db.create_all()

@login.user_loader
def load_user(id):
      return Users.query.get(int(id))

class Register(FlaskForm):
    username = StringField("User Name", validators = [DataRequired('Please input your username'), 
        Length(min = 3, max = 20, message = 'username must have at least 3 chars and max 20 chars')])
    email = StringField("Email Address", validators = [DataRequired(),  Email("Please input an appropriate email address")])
    password = PasswordField("Password", validators = [DataRequired(), EqualTo('confirm')])
    confirm = StringField("Confirm", validators = [DataRequired()])
    submit = SubmitField("Register")

    def validate_username(self, field):
        if Users.query.filter_by(username = field.data).first() :
            raise ValidationError("Your name has been register !!!")
        
    def validate_email(self, field):
        if Users.query.filter_by(email = field.data).first() :
            raise ValidationError("Your email has been register !!!")
        
class Login(FlaskForm):
    email = StringField("Email Address", validators = [DataRequired(), Email("Please input an appropriate email address")])
    password = PasswordField("Password", validators = [DataRequired()])
    submit = SubmitField("Login")
    
class NewPost(FlaskForm):
    title = StringField("Blog Title", validators = [DataRequired('Please input blog title'), 
        Length(min = 3, max = 255, message = 'title must have at least 3 chars and max 255 chars')])
    body = StringField("Blog Body", validators = [DataRequired('Please input blog body'), 
        Length(min = 3, max = 1000, message = 'username must have at least 3 chars and max 1000 chars')])
    submit = SubmitField('Post')
  
class NewComment(FlaskForm):
    body = StringField("Comment content", validators = [DataRequired('Please input blog body'), 
        Length(min = 3, max = 1000, message = 'username must have at least 3 chars and max 1000 chars')])
    submit = SubmitField('Comment')
    
@app.route('/register', methods = ['POST', 'GET'])
def register():
    form = Register()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_user = Users(username = form.username.data,
                             email = form.email.data,)
            new_user.set_pass(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('main'))
        else:
            for field_name, errors in form.errors.items():
                flash(errors)
            return redirect(url_for('register'))
    return render_template('register.html', form = form)

@app.route('/login', methods = ['POST', 'GET'])
def login():
    form = Login()
    if request.method == 'POST':
        check = Users.query.filter_by(email = form.email.data).first()
        if check :
            if check.check_pass(form.password.data):
                login_user(check)
                return redirect(url_for('profile'))
        else:
            flash(['email address or password was wrong !!! '])
            return redirect(url_for('login'))
    return render_template('login.html', form = form)

@app.route('/profile', methods = ['POST','GET'])
@login_required
def profile():
    post = Posts.query.filter_by(id=id).first()
    users = Users.query.all()
    return render_template('profile.html',users = users, post = post)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))
    
@app.route('/newpost', methods = ['POST', 'GET'])
@login_required
def newpost():
    form = NewPost()
    if request.method == 'POST':
        newpost = Posts(title = form.title.data,
                        body = form.body.data,
                        created = datetime.now())
        current_user.posts.append(newpost)
        db.session.add(newpost)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template("createpost.html", form = form)

@app.route('/editpost/<id>', methods = ['POST', 'GET'])
def editpost(id):
    form = NewPost()
    post = Posts.query.filter_by(id = id, author = current_user.id).first()
    if not post:
        flash([['you are not allow to edit the post']])
        return redirect(url_for('main'))
    else:
        if request.method == 'POST':
            post.title = form.title.data
            post.body = form.body.data
            post.uploaded = datetime.now()
            db.session.commit()
    return render_template('editpost.html', form = form, post = post)

@app.route('/singlepost')
def single_post():
    pass

@app.route('/posts/<id>/comments', methods = ['POST','GET'])
def new_comment(id):
    if request.method == 'POST':
        form = NewComment()
        if form.validate_on_submit():
            post = Posts.query.filter_by(id = id).first()
            c = Comments(body = form.body.data,
                        created = datetime.now(),
                        # author = current_.user.id,
                        # post = id,
                        )
            current_user.comments.appened(c)    #author
            post.comments.append(c)             #post
            db.session.add(c)
            db.session.commit()
        else:
            for field_name, errors in form.errors.items():
                flash(errors)
            return redirect(url_for('new_comment'))
                
    return render_template('new_comment.html')
    

@app.route('/')
def main():
    posts = Posts.query.all()
    return render_template('home.html', posts = posts)

if __name__ == "__main__":
    app.run(debug = True)