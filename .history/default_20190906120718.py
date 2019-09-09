import os
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

#setting
app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SECRET_KEY']="SUPERSECRET"

migrate = Migrate(app,db)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


#setting connection
POSTGRES = {
    'user': "khoa",
    'pw': "zzz",
    'db': 'bloghehe',
    'host': "localhost",
    'port': 5432,
}
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES







#define models

class Users(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String, nullable=False, unique=True)
  email = db.Column(db.String, nullable=False, unique=True)
  password = db.Column(db.String, nullable=False)
  posts = db.relationship("Posts", backref="users", lazy="dynamic")
  comments = db.relationship("Comments", backref="users", lazy="dynamic")

  def set_pass(self,passw):
    self.password =  generate_password_hash(passw)
  def check_pass(self,passw):
    return check_password_hash(self.password,passw)

class Posts(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String, nullable=False)
  body = db.Column(db.String, nullable=False)
  created = db.Column(db.DateTime, nullable=False)
  updated = db.Column(db.DateTime)
  author =  db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
  comments = db.relationship('Comments', backref="posts", lazy="dynamic")

class Comments(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  body = db.Column(db.String, nullable=False)
  created = db.Column(db.DateTime, nullable=False)
  updated = db.Column(db.DateTime)
  author =  db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
  post = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)



#define forms
class Register(FlaskForm):
  username = StringField("User Name", validators=[DataRequired("Please input your username"), Length(min=3, max=20, message="username must have at least 3 char and max 20 chars")])
  email = StringField("Email address", validators=[DataRequired(), Email("Please input an appropriate email address")])
  password = StringField("Password", validators=[DataRequired(), EqualTo("confirm")])
  confirm = StringField("Password", validators=[DataRequired()])
  submit = SubmitField("Register")

  def validate_username(self, field):
        if Users.query.filter_by(username=field.data).first() :
            raise ValidationError("Your username has been registered!!")
  def validate_email(self, field):
        if Users.query.filter_by(email=field.data).first() :
            raise ValidationError("Your email has been registered!!")


class Login(FlaskForm):
  email = StringField("Email address", validators=[DataRequired(), Email("Please input an appropriate email address")])
  password = PasswordField("Password", validators=[DataRequired()])
  submit = SubmitField("Login")

class NewPost(FlaskForm):
  title = StringField("Blog Title", validators=[DataRequired(), Length(min=3,max=255, message="min 3, max 255")])
  body = StringField("Content", validators=[DataRequired(), Length(min=3,max=10000, message="min 3, max 10000")])
  submit = SubmitField("Post")

class New_comment(FlaskForm):
  body = StringField("Comment content", validators=[DataRequired(), Length(min=3, max=1000, message="min 3, max 1000")])
  submit = SubmitField("Comment")

@app.route('/register', methods=['post','get'])
def register():
  form = Register()
  
  if request.method=="POST":
    if form.validate_on_submit(): 
      new_user = Users(username = form.username.data,
                        email = form.email.data,
                        )
      new_user.set_pass(form.password.data)
      db.session.add(new_user)
      db.session.commit()
      return redirect(url_for("home"))
    else:
      for field_name, errors in form.errors.items():
          flash(errors)
      return redirect((url_for('register')))
  return render_template('register.html', form = form)

@app.route('/login', methods=['post','get'])
def login():
  form = Login()
  if request.method == 'POST':
    check = Users.query.filter_by(email=form.email.data).first()
    if check :
      if check.check_pass(form.password.data):
        login_user(check)
        return redirect(url_for("home"))
    else:
      flash(["email address not exist"])
      return redirect(url_for('register'))
  return render_template('login.html', form = form)

@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('login'))

@app.route('/')
def home():
  posts = Posts.query.all()
  return render_template('index.html', posts = posts)
  

@app.route('/newpost', methods=['post', 'get'])
@login_required
def newpost():
  form = NewPost()
  if request.method == 'POST':
    new_post = Posts(title=form.title.data,
                    body=form.body.data,
                    created = datetime.now())
    current_user.posts.append(new_post)
    db.session.add(new_post)
    db.session.commit()
    return "ok"
  return render_template('newpost.html', form=form)

@app.route('/editpost/<id>', methods=['post','get'])
@login_required
def edit_post(id):
  form = NewPost()
  post = Posts.query.filter_by(id=id, author = current_user.id).first()
  if not post:
    flash([["you are not allowed to edit this post"]])
    return redirect(url_for("home"))
  else:
    if request.method == 'POST':
      post.title = form.title.data
      post.body = form.body.data
      post.updated = datetime.now()
      db.session.commit()
      return "ok"
      # return redirect(url_for('post'))
  return render_template('editpost.html', form = form )

@app.route('/delete_post/<id>', methods=['get'])
@login_required
def delete_post(id):
  post = Posts.query.filter_by(id=id, author=current_user.id).first()
  if post:
    db.session.delete(post)
    db.session.commit()
  else: 
    flash(['You are not allowed to delete this post'])
  return redirect(url_for('home'))

@app.route('/single_post/<id>', methods=['get'])
def single_post(id):
  post = Posts.query.filter_by(id=id).first()  # 1 item
  comments = post.comments.all()  # a list 
  return render_template('single_post.html', post = post, comments = comments)


@app.route('/posts/<id>/comments', methods=['POST','GET'])
def new_comment(id):
  form = New_comment()
  if request.method == 'POST':
    if form.validate_on_submit():
      post = Posts.query.filter_by(id=id).first()
      c = Comments(body=form.body.data,
                    created = datetime.now(),
                    # author = current_user.id,
                    )
      current_user.comments.append(c) # autho
      post.comments.append(c)      # post
      db.session.add(c)
      db.session.commit()
      return redirect(url_for('single_post', id=id))
    else:
      for field_name, errors in form.errors.items():
          flash(errors)
      return redirect((url_for('new_comment')))
  return render_template('new_comment.html', form = form)
    


@app.route('/khoa', methods=['get','options',"DELETE"])
def khoa():
  if request.method == "DELETE":
    return "KHOA IS COOL"
  return "NOPE"


if __name__ == "__main__":
  app.run(debug=True, port=5001)
