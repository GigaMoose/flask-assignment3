# Matt Saner
# Please check reference.txt in GitHub for various tutorials that helped me complete this assignment


from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, IntegerField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, Optional, NumberRange, Regexp
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy import exc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import phonenumbers
import os
import subprocess
import sys


#basedir = os.path.abspath(os.path.dirname(__file__))
#basedir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'X3ZQRvCbYeQx4rAVhKkb'
#app.config['SQLALCHEMY_DATABASE_URI'] =\
#    'sqlite:////' + os.path.join(basedir, 'assignment2db.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
    phone = db.Column(db.String(11))

class Queries(db.Model):
    __tablename__ = 'queries'
    QueryID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80))
    QueryText = db.Column(db.String(5000))
    QueryResult = db.Column(db.String(5000))

class AuditLogs(db.Model):
    __tablename__ = 'auditlogs'
    AuditID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80))
    LogInTime = db.Column(db.DateTime)
    LogOutTime = db.Column(db.DateTime, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired()])
    pword = PasswordField('password', validators=[InputRequired()])
    #uname = StringField('username', validators=[InputRequired(), Regexp(r'^[A-Za-z0-9_]+$/')])
    #pword = PasswordField('password', validators=[InputRequired(), Regexp(r'^[A-Za-z0-9_]+$/')])
    #uname = StringField('username', validators=[InputRequired(), Regexp(r'^\w+$')])
    #pword = PasswordField('password', validators=[InputRequired(), Regexp(r'^\w+$')])
    #phone = IntegerField('phone', validators=[Optional(), NumberRange(min=10000000000,max=99999999999)], id='2fa')
    phone = IntegerField('phone', validators=[Optional()], id='2fa')

class RegisterForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired()])
    pword = PasswordField('password', validators=[InputRequired()])
    #uname = StringField('username', validators=[InputRequired(), Regexp(r'^\w+$')])
    #pword = PasswordField('password', validators=[InputRequired(), Regexp(r'^\w+$')])
    #phone = IntegerField('phone', validators=[Optional(), NumberRange(min=10000000000,max=99999999999)], id='2fa')
    phone = IntegerField('phone', validators=[Optional()], id='2fa')

class SpellcheckForm(FlaskForm):
    inputtext = TextAreaField('Input Text', id='inputtext')
    textout = TextAreaField('Output Text', id='textout')
    misspelled = TextAreaField('Misspelled Text', id='misspelled')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    #form = FlaskForm(csrf_enabled=False)
    outcome = ''
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.uname.data).first()
        #login_user(user)
        if user:
            if check_password_hash(user.password, form.pword.data):
                if (user.phone) is not None:
                    if (int((user.phone)) != form.phone.data):
                        outcome = 'Two-factor failure'
                        return render_template('login.html', form=form, outcome=outcome)
                    elif (int((user.phone)) == form.phone.data):
                        outcome = 'success'
                        login_user(user)
                        datetimestamp = datetime.now()
                        loginaudits = AuditLogs(username=user.username, LogInTime=datetimestamp)
                        db.session.add(loginaudits)
                        db.session.commit()
                        return render_template('login.html', form=form, outcome=outcome)
                else:
                    outcome = 'success'
                    login_user(user)
                    datetimestamp = datetime.now()
                    loginaudits = AuditLogs(username=user.username, LogInTime=datetimestamp)
                    db.session.add(loginaudits)
                    db.session.commit()
                    return render_template('login.html', form=form, outcome=outcome)
            else:
                outcome = 'incorrect password'
                return render_template('login.html', form=form, outcome=outcome)
        if not user:
            outcome = 'incorrect user'
            return render_template('login.html', form=form, outcome=outcome)

        #return '<h1>Invalid username or password or phone</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('login.html', form=form, outcome=outcome)

@app.route('/register', methods=['GET', 'POST'])
def register():
    outcome = ''
    if current_user.is_authenticated:
        return redirect(url_for('spell_check'))

    form = RegisterForm()
    #form = FlaskForm(csrf_enabled=False)

    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.pword.data, method='sha256')
            new_user = User(username=form.uname.data, password=hashed_password, phone=form.phone.data)
            db.session.add(new_user)
            db.session.commit()

            #return '<p id="success">'
            #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
            #return '<p id="failure">'
            outcome = 'success'
            return render_template('register.html', form=form, outcome=outcome)
        except exc.IntegrityError:
            db.session.rollback()
            outcome = 'failure'
            return render_template('register.html', form=form, outcome=outcome)
    
    return render_template('register.html', form=form)


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    if current_user.is_authenticated:
        form = SpellcheckForm()
        #form = FlaskForm(csrf_enabled=False)

        if form.validate_on_submit():
            inputtext = form.inputtext.data
            with open("test.txt", "w") as testfile:
                testfile.write(str(inputtext))
                testfile.close
            runspellcheck = subprocess.check_output(['./a.out','./test.txt', './wordlist.txt']).decode('utf-8')
            misspelledwords = runspellcheck.replace("\n", ", ").strip().strip(',')
            #print('Hello world!', file=sys.stderr)
            #print(misspelledwords, file=sys.stderr)
            #print(runspellcheck, file=sys.stderr)
            print(current_user.username, file=sys.stderr)
            queryhistory = Queries(username=current_user.username, QueryText=inputtext, QueryResult=misspelledwords)
            db.session.add(queryhistory)
            db.session.commit()
            return render_template('spellcheck2.html', form=form, textout=inputtext, badwords=misspelledwords)

        outcome = 'success'
        return render_template('spellcheck2.html', form=form, outcome=outcome)

@app.route('/history', methods=['GET'])
@login_required
def history():
    if current_user.is_authenticated:
        if current_user.username == 'admin':
            fullhistory = Queries.query.all()
        else:
            fullhistory = Queries.query.filter_by(username=current_user.username)
        
        querycount = Queries.query.filter_by(username=current_user.username).count()
        
        return render_template('history.html', queryid=fullhistory, querycount=querycount)
        
@app.route('/history/query<id>', methods=['GET'])
@login_required
def queryreview(id):
    if current_user.is_authenticated:
        if current_user.username == 'admin':
            queryreview = Queries.query.filter_by(QueryID = id).first()
        else:
            queryreview = Queries.query.filter_by(QueryID = id, username=current_user.username).first()
    
        return render_template('queryreview.html', queryreview=queryreview)

@app.route('/logout')
#@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
