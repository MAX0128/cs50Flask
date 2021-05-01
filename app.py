from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.urls import url_parse
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = "my_secret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myDB.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

# create login manager
login_manager = LoginManager()
login_manager.init_app(app)

hashed_password = generate_password_hash("noONEwillEVERguessTHIS")

# users model


class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), index=True, unique=True)
    password = db.Column(db.String(50), index=False, unique=False)
    email = db.Column(db.String(50), index=True, unique=True)
    notes = db.relationship('Notes', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '<User {}>'.format(self.name)


# notes model


class Notes(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('courses.course_id'))
    title = db.Column(db.String(100), index=True, unique=False)
    notes = db.Column(db.Text, index=False, unique=False)

# courses models


class Courses(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, index=True, unique=False)
    collage = db.Column(db.String(50), index=True, unique=False)
    course_name = db.Column(db.String(80), index=True, unique=False)
    instructor = db.Column(db.String(20), index=True, unique=False)
    notes = db.relationship('Notes', backref='course', lazy='dynamic')


# Forms


class RegisterForm(FlaskForm):
    user = StringField("Username:", validators=[DataRequired()])
    password = PasswordField("Password:", validators=[DataRequired()])
    passconfirm = PasswordField("Password Confirmation:", validators=[
        DataRequired(), EqualTo('password')])
    email = StringField("School Email:", validators=[DataRequired(), Email()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    userlog = StringField("Username", validators=[DataRequired()])
    passwordlog = PasswordField("Password:", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submitlog = SubmitField("Login")


class CreateForm(FlaskForm):
    course_id = StringField("course_id")
    course = StringField("Course")
    title = StringField("Title(week, topic...)")
    notes = TextAreaField("Notes")
    submitnote = SubmitField("Submit")


class SearchCourse(FlaskForm):
    course = StringField("Course", validators=[DataRequired()])
    submit = SubmitField("Search", validators=[DataRequired()])


@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id))


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    form = RegisterForm()
    if form.validate_on_submit():
        try:
            user = Users(name=form.user.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()

            return redirect(url_for('login'))
        except:
            return "Invalid Username OR Username Taken"
    return render_template("register.html", title='Register', form=form)


@ app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    try:
        if request.method == "POST":
            if form.validate_on_submit():
                user = Users.query.filter_by(name=form.userlog.data).first()
                if user and user.check_password(form.passwordlog.data):
                    login_user(user, remember=form.remember.data)
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('index', _external=True, _scheme='http'))
                else:
                    flash('Invalid password or user do not exsist.')
                    return redirect(url_for('login', _external=True, _scheme='http'))
    except:
        return 'OOPS'
    return render_template('login.html', title='Login', form=form)


@app.route('/user/<name>', methods=["GET", "POST"])
@login_required
def user(name):
    user = current_user
    user = Users.query.filter_by(name=user.name).first()
    notes = Notes.query.filter_by(user_id=user.id)
    notelist = []
    for note in notes:
        course = Courses.query.filter_by(course_id=note.course_id).first()
        notelist.append(course)

    return render_template('user.html', user=user, notes=notes, notelist=notelist)


@app.route("/<note_id>", methods=["GET"])
@login_required
def note(note_id):
    user = current_user
    user = Users.query.filter_by(name=user.name).first()
    text = Notes.query.filter_by(id=note_id).first()
    return render_template("note.html", user=user, text=text)


@app.route("/newnote/<name>", methods=["GET", "POST"])
@login_required
def newnote(name):
    # create new notes
    form = CreateForm()
    user = current_user
    user = Users.query.filter_by(name=user.name).first()
    if form.validate_on_submit():

        note = Notes(user_id=user.id, course_id=int(form.course_id.data),
                     title=form.title.data, notes=form.notes.data)
        course = Courses.query.filter_by(
            course_id=int(form.course_id.data)).first()
        name = current_user.name
        if course:
            db.session.add(note)
            db.session.commit()

            flash(
                f"{user.name}, you successfully added {note.title} to your notelist!")
            return redirect(url_for('user', name=name))
        else:
            return render_template("create_fail.html")
    return render_template("create.html", createForm=form)


@login_manager.unauthorized_handler
def unauthorized():
    return "Sorry you must be logged in to view this page"


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/<note_id>/delete")
@login_required
def delete(note_id):
    name = current_user.name
    note = Notes.query.filter_by(id=note_id).first()
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('user', name=name))


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    formCourse = SearchCourse()

    if formCourse.validate_on_submit():
        courseimput = "%{}%".format(formCourse.course.data)
        note_course = Courses.query.filter(
            Courses.course_name.like(courseimput)).all()
        return render_template("search.html", note_course=note_course, formCourse=formCourse)

    return render_template("search.html", formCourse=formCourse)
