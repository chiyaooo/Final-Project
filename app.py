from flask import Flask
from flask import render_template, redirect, request, flash, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, DateField, SubmitField,DecimalField,PasswordField,BooleanField
from wtforms.validators import DataRequired,ValidationError,Email, EqualTo
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps
from sqlalchemy import or_
import pymysql
import secrets
import datetime
from datetime import date, timedelta
import os


#conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(secrets.dbuser, secrets.dbpass, secrets.dbhost, secrets.dbname)
dbuser = os.environ.get('DBUSER')
dbpass = os.environ.get('DBPASS')
dbhost = os.environ.get('DBHOST')
dbname = os.environ.get('DBNAME')

conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(dbuser, dbpass, dbhost, dbname)
app = Flask(__name__)





login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger'

app.config['SECRET_KEY']='SuperSecretKey'

class SQLAlchemy(_BaseSQLAlchemy):
     def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True

app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class cheyao_casemap(db.Model):
    states = db.Column(db.String(2), primary_key=True)
    cases = db.Column(db.Integer)
    recovered = db.Column(db.Integer)
    deaths = db.Column(db.Integer)
    fatality = db.Column(db.String(25))

    def __repr__(self):
        return "states: {0} | cases: {1} | recovered: {2} | deaths: {3} | fatality: {4}".format(self.states, self.cases, self.recovered, self.deaths, self.fatality)

class cheyao_casesummary(db.Model):
    location = db.Column(db.String(45), primary_key=True)
    totalCases = db.Column(db.Integer)
    totalRecovered = db.Column(db.Integer)
    totalDeaths = db.Column(db.Integer)
    fatality = db.Column(db.String(25))
    date = db.Column(db.Date)
    def __repr__(self):
        return "location: {0} | totalCases: {1} | totalRecovered: {2} | totalDeaths: {3} | fatality: {4} | date: {5}".format(self.location, self.totalCases, self.totalRecovered, self.totalDeaths, self.fatality, self.date)


class CaseForm(FlaskForm):
    states = StringField('States: ',validators=[DataRequired()])
    cases = IntegerField('Cases:', validators=[DataRequired()])
    recovered = IntegerField('Revocered:', validators=[DataRequired()])
    deaths = IntegerField('Deaths:', validators=[DataRequired()])
    fatality = StringField('Fatality: ', validators=[DataRequired()])


class CaseSummForm(FlaskForm):
    location = StringField('Location: ',validators=[DataRequired()])
    totalCases = IntegerField('Total Cases:', validators=[DataRequired()])
    totalRecovered = IntegerField('Total Recovered:', validators=[DataRequired()])
    totalDeaths = IntegerField('Total Deaths:', validators=[DataRequired()])
    fatality = StringField('Fatality:', validators=[DataRequired()])
    date = DateField('Date:',validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class NewUserForm(FlaskForm):
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = IntegerField('Access: ')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class UserDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    access = IntegerField('Access: ')

class AccountDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])


ACCESS = {
    'guest': 0,
    'user': 1,
    'admin': 2
}

class User(UserMixin, db.Model):
    __tablename__ = 'cheyao_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer)

    def __init__(self, name, email, username, access=ACCESS['guest']):
        self.id = ''
        self.name = name
        self.email = email
        self.username = username
        self.password_hash = ''
        self.access = access

    def is_admin(self):
        return self.access == ACCESS['admin']

    def is_user(self):
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        return self.access >= access_level

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {0}>'.format(self.username)




@login.user_loader
def load_user(id):
    return User.query.get(int(id))  #if this changes to a string, remove int


### custom wrap to determine access level ###
def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: #the user is not logged in
                return redirect(url_for('login'))

            #user = User.query.filter_by(id=current_user.id).first()

            if not current_user.allowed(access_level):
                flash('You do not have access to this resource.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error('Server Error: %s', (error))
    return render_template('index.html'), 500


@app.route('/')
def index():
    return render_template('index.html', pageTitle='COVID', legend='Home')

@app.route('/about')
def about():
    return render_template('about.html', pageTitle='About')

@app.route('/contact')
def contact():
    return render_template('contact.html', pageTitle='Contact')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',  pageTitle='Register | My Flask App', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        flash('You are now logged in', 'success')
        return redirect(next_page)
    return render_template('login.html',  pageTitle='Login | My Flask App', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = User.query.get_or_404(current_user.id)
    form = AccountDetailForm()

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.set_password(form.password.data)

        db.session.commit()
        flash('Your account has been updated.', 'success')
        return redirect(url_for('account'))

    form.name.data = user.name
    form.email.data = user.email

    return render_template('account_detail.html', form=form, pageTitle='Your Account')

@app.route('/cases')
@requires_access_level(ACCESS['guest'])
def cases():
    all_cases = cheyao_casemap.query.all()
    return render_template('cases.html', cases=all_cases, pageTitle='Cases', legend='Cases')

@app.route('/casesSum')
@requires_access_level(ACCESS['guest'])
def casesSum():
    all_casesSum = cheyao_casesummary.query.all()
    return render_template('casesSum.html', cases=all_casesSum, pageTitle='Cases Summary', legend='Cases Summary')

@app.route('/searchcases', methods=['GET', 'POST'])
@requires_access_level(ACCESS['guest'])
def search_cases():
    if request.method =='POST':
        form = request.form
        search_value = form['search_cases']
        search = "%{0}%".format(search_value)
        results = cheyao_casemap.query.filter( or_(cheyao_casemap.states.like(search), cheyao_casemap.cases.like(search))).all()
        return render_template('cases.html', cases=results, pageTitle='Cases', legend='Search Results')
    else:
        return redirect('/')

@app.route('/case/new', methods=['GET', 'POST'])
@requires_access_level(ACCESS['user'])
def add_case():
    form = CaseForm()
    if form.validate_on_submit():
        case = cheyao_casemap(states=form.states.data, cases=form.cases.data, recovered=form.recovered.data, deaths=form.deaths.data, fatality=form.fatality.data)
        db.session.add(case)
        db.session.commit()
        return redirect('/cases')

    return render_template('add_case.html', form=form, pageTitle='Add A New Case', legend="Add A New Case")

@app.route('/case/<string:states>', methods=['GET','POST'])
@requires_access_level(ACCESS['guest'])
def case(states):
    case = cheyao_casemap.query.get_or_404(states)
    return render_template('case.html', form=case, pageTitle='Case Detail', legend='Case Detail')


@app.route('/case/<string:states>/update', methods=['GET','POST'])
@requires_access_level(ACCESS['user'])
def update_case(states):
    case = cheyao_casemap.query.get_or_404(states)
    form = CaseForm()

    if form.validate_on_submit():
        case.states = form.states.data
        case.cases = form.cases.data
        case.recovered = form.recovered.data
        case.deaths = form.deaths.data
        case.fatality = form.fatality.data
        db.session.commit()
        return redirect('/cases')

    form.states.data = case.states
    form.cases.data = case.cases
    form.recovered.data = case.recovered
    form.deaths.data = case.deaths
    form.fatality.data = case.fatality
    return render_template('update_case.html', form=form, pageTitle='Update Case',legend="Update A Case")

@app.route('/case/<string:states>/delete', methods=['POST'])
@requires_access_level(ACCESS['user'])
def delete_case(states):
    if request.method == 'POST': #if it's a POST request, delete the material from the database
        case = cheyao_casemap.query.get_or_404(states)
        db.session.delete(case)
        db.session.commit()
        flash('Case was successfully deleted!')
        return redirect('/cases')
    else: #if it's a GET request, send them to the home page
        return redirect('/cases')

if __name__ == '__main__':
    app.run(debug=True)

app.config['DEBUG'] = True
