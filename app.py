import os
import uuid
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from functools import wraps

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv(
    "secretKey", "40942f9900788e2d16945de4e6211ca44fa7759ee6f2e5f874b5f3cfba1a8d7b"
)


app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{os.getenv('user')}:{os.getenv('password')}@{os.getenv('host')}/{os.getenv('database')}"
)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "poolclass": NullPool}

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    deleted = db.Column(db.Boolean, default=False)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    completed = db.Column(db.Boolean, default=False)


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("Users", backref=db.backref("passwords", lazy=True))


key = os.getenv("encryptionKey")
cipher_suite = Fernet(key)


def protected(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()


@app.errorhandler(404)
def notFond(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internalError(e):
    return render_template("500.html"), 500


@app.route("/error")
def trigger_error():
    raise Exception("This is a simulated server error!")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(
            password, method="pbkdf2:sha1", salt_length=8
        )
        new_user = Users(
            firstname=firstname,
            lastname=lastname,
            email=email,
            username=username,
            password=hashed_password,
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            user = Users.query.filter_by(email=email).first()
            session["user_id"] = user.id
            session["username"] = user.username
            session["email"] = user.email
            session["firstname"] = user.firstname
            session["lastname"] = user.lastname
            flash("Account created successfully.", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            logging.error(f"Error Registering User: {e}")
            db.session.rollback()
            flash("Username or Email already exists.", "danger")
            return render_template("register.html")
    return render_template("register.html", title = "Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = Users.query.filter_by(email=email).first()
        if user and not user.deleted and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["email"] = user.email
            session["firstname"] = user.firstname
            session["lastname"] = user.lastname
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        elif user and user.deleted:
            flash("Account has been deleted. Please contact support.", "login")
        else:
            flash("Invalid login credentials.", "login")
    return render_template("login.html", title="Login")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("email", None)
    session["_flashes"].clear()
    return redirect(url_for("login"))


@app.route("/terms-and-conditions/")
def tnc():
    return render_template("tnc.html")


@app.route("/privacy-policy/")
def pp():
    return render_template("ppolicy.html")


@app.route("/test/")
def test():
    passwords=Passwords.query.filter_by(user_id=session["user_id"]).all()
    return render_template(
        "test.html",
        passwords=passwords
    )


@app.route("/passwords", methods=["GET", "POST"])
@protected
def passwords():
    if request.method == "POST":
        title = request.form["title"]
        username = request.form["username"]
        password = request.form["password"]
        domain = request.form["domain"]

        encrypted_password = encrypt_password(password)
        new_password = Passwords(
            title=title,
            username=username,
            password=encrypted_password,
            domain=domain,
            user_id=session["user_id"],
        )

        try:
            db.session.add(new_password)
            db.session.commit()
            flash("Password saved successfully.", "success")
            return redirect(url_for("passwords"))
        except Exception as e:
            logging.error(f"Error Saving Password: {e}")
            db.session.rollback()
            flash("An error occurred while saving the password.", "danger")

    passwords = Passwords.query.filter_by(user_id=session["user_id"]).all()
    # Decrypt passwords before displaying them
    for p in passwords:
        p.password = decrypt_password(p.password)
    return render_template(
        "password.html",
        passwords=passwords,
        current_path=request.path,
        title="Passwords"
    )


@app.route("/passwords/delete/<id>")
@protected
def Passdelete(id):


    password_to_delete = Passwords.query.get_or_404(id)

    try:
        db.session.delete(password_to_delete)
        db.session.commit()
        return redirect("/passwords")
    except Exception as e:
        logging.error(f"Error Deleting Password: {e}")
        db.session.rollback()
        return "Error Deleting Password"


@app.route("/")
@protected
def dashboard():

    # Query database to get counts
    total_tasks = Todo.query.filter_by(user_id=session["user_id"]).count()
    total_passwords = Passwords.query.filter_by(user_id=session["user_id"]).count()
    pending_tasks = Todo.query.filter_by(
        user_id=session["user_id"], completed=False
    ).count()
    completed_tasks = Todo.query.filter_by(
        user_id=session["user_id"], completed=True
    ).count()

    return render_template(
        "dashboard.html",
        current_path=request.path,
        total_tasks=total_tasks,
        total_passwords=total_passwords,
        pending_tasks=pending_tasks,
        completed_tasks=completed_tasks,
        title="Dashboard",
    )


@app.route("/tasks", methods=["POST", "GET"])
@protected
def tasks():

    if request.method == "POST":
        task = request.form["content"]
        new_task = Todo(content=task, user_id=session["user_id"])
        db.session.add(new_task)
        db.session.commit()
        return redirect("/tasks")
    else:
        tasks = (
            Todo.query.filter_by(user_id=session["user_id"])
            .order_by(Todo.date_created)
            .all()
        )
        return render_template(
            "task.html", tasks=tasks, current_path=request.path, title="Tasks"
        )


@app.route("/delete/<id>")
@protected
def delete(id):

    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect("/")
    except Exception as e:
        logging.error(f"Error Deleting Task: {e}")
        db.session.rollback()
        return "Error Deleting Task"


@app.route("/update/<id>", methods=["GET", "POST"])
@protected
def update(id):


    task = Todo.query.get_or_404(id)
    if request.method == "POST":
        task.content = request.form["content"]

        try:
            db.session.commit()
            return redirect("/")
        except Exception as e:
            logging.error(f"Error Updating Task: {e}")
            db.session.rollback()
            return "Error Updating Task"
    else:
        return render_template("update.html", task=task)


@app.route("/settings", methods=["GET", "POST"])
@protected
def settings():

    user_id = session["user_id"]
    user = db.session.get(Users, user_id)

    if request.method == "POST":
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        email = request.form.get("email")
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")

        # Verify current password before updating
        if not check_password_hash(user.password, current_password):
            flash("Incorrect current password. Please try again.", "danger")
            return render_template("settings.html", user=user)

        # Hash new password if provided
        if new_password:
            user.password = generate_password_hash(
                new_password, method="pbkdf2:sha256", salt_length=8
            )

        # Update other details
        user.firstname = firstname
        user.lastname = lastname
        user.email = email

        try:
            db.session.commit()
            flash("Settings updated successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(
                "An error occurred while updating your information. Please try again.",
                "danger",
            )

    return render_template(
        "settings.html", user=user, current_path=request.path, title="Settings"
    )


@app.route("/update_user", methods=["POST"])
@protected
def update_user():
    user_id = session["user_id"]
    user = db.session.get(Users, user_id)

    # Ensure the user exists
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("settings"))

    # Get updated details from the form
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")

    # Ensure the user_id is not being modified
    if user.id != user_id:
        flash("You cannot modify the user ID.", "danger")
        return redirect(url_for("settings"))

    # Update user details
    user.firstname = firstname
    user.lastname = lastname
    user.email = email

    try:
        db.session.commit()
        flash("User details updated successfully!", "success")
        return redirect(url_for("settings"))
    except Exception as e:
        db.session.rollback()
        flash(
            "An error occurred while updating your details. Please try again.", "danger"
        )
        return redirect(url_for("settings"))


@app.route("/delete_user", methods=["POST"])
@protected
def delete_user():
    try:
        user_id = session["user_id"]
        user = Users.query.get(user_id)

        if not user:
            flash("User not found!", "danger")
            return redirect(url_for("settings"))

        user.deleted = True
        db.session.commit()

        session.clear()
        flash("Your account has been deactivated successfully.", "success")
        return redirect(url_for("dashboard")) 
    except Exception as e:
        db.session.rollback()
        flash(
            "An error occurred while trying to deactivate your account. Please try again.",
            "danger",
        )
        return redirect(url_for("settings"))


if __name__ == "__main__":
    app.run(debug=True)
