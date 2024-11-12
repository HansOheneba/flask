import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import logging
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from werkzeug.security import generate_password_hash, check_password_hash




load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("secretKey")
logging.basicConfig(level=logging.INFO)



app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{os.getenv('user')}:{os.getenv('password')}@{os.getenv('host')}/{os.getenv('database')}"
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "poolclass": NullPool
}

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha1', salt_length=8)
        new_user = Users(
            firstname=firstname,
            lastname=lastname,
            email=email,
            username=username,
            password=hashed_password
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Error Registering User: {e}")
            db.session.rollback()
            flash("Username or Email already exists.", "danger")
            return render_template('register.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = Users.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            flash("Login successful.", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/terms-and-conditions/')
def tnc():
    return render_template('tnc.html')
@app.route('/privacy-policy/')
def pp():
    return render_template('ppolicy.html')

@app.route('/', methods=['POST','GET'])
def index():
    if request.method == 'POST':
        task = request.form['content']
        new_task = Todo(content=task)
        db.session.add(new_task)
        db.session.commit()
        return redirect("/")
    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        return render_template("index.html", tasks=tasks)

@app.route('/delete/<id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        logging.error(f"Error Deleting Task: {e}")
        db.session.rollback()
        return 'Error Deleting Task'
    
@app.route('/update/<id>', methods=['GET', 'POST'])
def update(id):
    task = Todo.query.get_or_404(id)
    if request.method == 'POST':
        task.content = request.form['content']
        
        try:
            db.session.commit()
            return redirect('/')
        except Exception as e:
            logging.error(f"Error Updating Task: {e}")
            db.session.rollback()
            return 'Error Updating Task'
    else:
        return render_template('update.html', task=task)

if __name__ == "__main__":
    app.run(debug=True)
