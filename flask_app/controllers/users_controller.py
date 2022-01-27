from tkinter.messagebox import RETRY
from flask import render_template, redirect, session, request
from flask_app.models.user import User
from flask_app import app
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route("/")
def home():
    if "uuid" in session: # will send the user back to the success page if they has already logged in
        return redirect("/success")
    return render_template("index.html")

@app.route("/success")
def success():
    if "uuid" not in session: # will send the user back to the home page is they have not already logged in
        return redirect("/")
    return render_template("success.html", user = User.get_by_id({"id": session["uuid"]}))

@app.route("/register", methods=["POST"])
def register():
    if not User.validator(request.form): # validates the input
        return redirect("/")
    else:
        hash_browns = bcrypt.generate_password_hash(request.form["password"]) # hashes the password using bcrypt
        user_data = {**request.form, "password": hash_browns} # stores the hashed password and request.form in the variable
        session["uuid"] = User.create(user_data) # creates a new user with the hashed password and stores it in session
        return redirect("/success")

@app.route("/login", methods=["POST"])
def login():
    if not User.login_validator(request.form):
        return redirect("/")
    else:
        user = User.get_by_email({"email": request.form["email"]})
        session["uuid"] = user.id
        return redirect("/success")

@app.route("/logout")
def logout():
    session.clear() # will clear session when logged out preventing from accessing the success page
    return redirect("/") # redirect home