from flask import Flask,render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import os
import bcrypt



basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.secret_key = 'my secret key'

db= SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User( UserMixin , db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hash = db.Column(db.String(120))
    def __repr__(self):
        return '<User %r>' % self.username

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods =['GET','POST'])
def login():
    if request.method=='POST':
        username = request.form.get("username")
      
        password = request.form.get("password")  

        user = User.query.filter_by(username=username).first()
        if user:
            if bcrypt.checkpw(password.encode('utf-8') , user.hash ):
                login_user(user)
                return redirect(url_for('home',p = user.username))


    return render_template('login.html')

@app.route('/register' , methods =['GET','POST'])
def register():
    if request.method=='POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # new_user = User.query.filter_by(email=email).first()

        # if new_user:
        #     flash("Email already exist")
        #     return redirect(url_for('login'))

        user = User(username=username, email= email, hash = hashed)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/home/<p>')
@login_required
def home(p):
    return render_template('home.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template('login.html')

if __name__=="__main__":
    app.run()



