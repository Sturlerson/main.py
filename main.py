from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from flask_wtf import FlaskForm

from sqlalchemy import Column, Integer, String, Text, ForeignKey, PickleType

from urllib3.packages.six import wraps
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

from forms import CreatePostForm
from flask_gravatar import Gravatar

import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
app.config['CKEDITOR_PKG_TYPE'] = 'full'

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://unzbruyxoozphc:6df434474765c77a619a6ac0a3cfd30560d1a3634ac3549faa42472b881e9138@ec2-54-228-218-84.eu-west-1.compute.amazonaws.com:5432/db4mni59h52trf"
app.config.from_object(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def admin_only(func):
    @wraps(func)
    def change(*args, **kwargs):
        if current_user.is_authenticated:
            user = User.query.filter_by(id=current_user.get_id()).first()
            if user.id == 1:
                return func(*args, **kwargs)
        else:
            return abort(403)
    return change

def check_if_admin():
    if current_user.is_authenticated:
        print(current_user.get_id())
        user = User.query.filter_by(id=current_user.get_id()).first()
        if user.id == 1:
            print("worked")
            return True
    else:
        return False

def check_user():
    if current_user.is_authenticated:
        return True
    else:
        return False

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True)
    password = Column(String(100))
    name = Column(String(1000))
    children = relationship("BlogPost", back_populates="parent")
    child = relationship("Comment", back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey('user.id'))
    author = Column(String(250), nullable=False)
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    parent = relationship("User", back_populates="children")
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    blogpost_id = Column(Integer, ForeignKey('blog_posts.id'))
    author_id = Column(Integer, ForeignKey('user.id'))
    author = relationship("User", back_populates="child")
    post = relationship("BlogPost", back_populates="comments")
    text = Column(Text, nullable=False)

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

@app.route('/')
def get_all_posts():
    admin = check_if_admin()
    verify = check_user()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, verify=verify, admin=admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if request.method == "POST":
        password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        email = form.email.data
        name = form.name.data
        check = User.query.filter_by(email=email).first()
        if check:
            return redirect(url_for("login", user_exists=True))
        user = User(email=email,password=password,name=name)
        db.session.add(user)
        db.session.commit()
        return render_template("register.html", form=form)

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET","POST"] )
def login():
    verify = check_user()
    form = RegisterForm()
    if request.method == "POST":
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                login_user(user)
                return redirect(url_for('get_all_posts', verify=verify))
            return render_template("login.html", form=form, verify=verify)
    if request.args.get("user_exists"):
        flash("You've already signed up with that email, Login instead")
    return render_template("login.html", form=form, verify=verify)


@app.route('/logout')
@login_required
def logout():
    verify = check_user()
    logout_user()
    return redirect(url_for('get_all_posts', verify=verify))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comments = Comment.query.all()
    comments_ = []
    if comments != None:
        comments_ = comments
    form = CommentForm()
    verify = check_user()
    requested_post = BlogPost.query.get(post_id)
    if request.method == "POST":
        comment = request.form.get('comment_text')
        user = User.query.filter_by(id=current_user.get_id()).first()
        comment_database = Comment(
            blogpost_id = requested_post.id,
            author_id = user.id,
            text = comment)
        db.session.add(comment_database)
        db.session.commit()
        return render_template("post.html", post=requested_post, verify=verify, form=form, comments=comments_, post_id=post_id)
    return render_template("post.html", post=requested_post, verify=verify, form=form, comments=comments_, post_id=post_id)


@app.route("/about")
def about():
    verify = check_user()
    return render_template("about.html", verify=verify)


@app.route("/contact")
def contact():
    verify = check_user()
    return render_template("contact.html", verify=verify)

@app.route("/new-post", methods=["GET","POST"])
@admin_only
def add_new_post():
    user = User.query.filter_by(id=current_user.get_id()).first()
    author =  User.query.filter_by(id=current_user.get_id()).first()
    verify = check_user()
    form = CreatePostForm()
    if request.method == "POST":
        new_post = BlogPost(
            title=form.title.data,
            parent_id = user.id,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=author.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", verify=verify))
    return render_template("make-post.html", form=form, verify=verify)

@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    verify = check_user()
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, verify=verify))

    return render_template("make-post.html", form=edit_form, verify=verify)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    verify = check_user()
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', verify=verify))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
