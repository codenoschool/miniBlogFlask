from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import os

dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "superSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String())

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Length(max=50, message="Máx 50."), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(max=80, message="Máx 80.")])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Length(max=50, message="Máx 50."), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(max=80, message="Máx 80.")])
    remember = BooleanField("Remember me")
    submit = SubmitField("Log In")

@app.route("/")
def index():
    return "Welcome to this little blog."

@app.route("/posts")
def posts():
    posts = Posts.query.all()

    return render_template("posts.html", posts=posts)

@app.route("/post/<int:id>")
def post(id):
    post = Posts.query.get(id)

    return render_template("post.html", post=post)

@app.route("/new/post", methods=["GET", "POST"])
def newPost():

    if request.method == "POST":
        new_post = Posts(title=request.form["title"], content=request.form["content"])
        db.session.add(new_post)
        db.session.commit()
        flash("The post was created successfully.")
        return redirect(url_for("posts"))

    return render_template("newPost.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = Users(email=form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("You've been registered successfully")
        return redirect(url_for("sigin"))

    return render_template("signup.html", form=form)

@app.route("/signin", methods=["GET", "POST"])
def signin():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password, form.password.data):
            return redirect(url_for("newPost"))
        return "Your credentials are invalid. Double check and try again."
    
    return render_template("signin.html", form=form)

@app.errorhandler(400)
def page_not_found(error):
    return render_template("page_not_found.html"), 400

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
