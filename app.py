# -*- coding: utf-8 -*-
import os
import time
import hashlib

from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_mongoengine import MongoEngine, Document
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField
from wtforms import StringField, PasswordField, IntegerField, SelectField
from wtforms.validators import Email, Length, InputRequired, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'I have a dream'
app.config['UPLOADED_PHOTOS_DEST'] = os.getcwd() + '/uploads'

app.config['MONGODB_SETTINGS'] = {
    'db': 'upload_video',
    'host': 'mongodb://localhost:27017/upload_video'
}

db = MongoEngine(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
patch_request_class(app, 100 * 1024 * 1024)  # set maximum file size 100MB


class User(UserMixin, db.Document):
    meta = {'collection': 'user_collection'}
    email = db.StringField(max_length=30)
    password = db.StringField()


class Video(db.Document):
    meta = {'collection': 'video_collection'}
    file_name = db.StringField(max_length=30)
    email = db.StringField(max_length=30)
    age = db.IntField()
    gender = db.StringField()


class UploadForm(FlaskForm):
    photo = FileField(validators=[FileAllowed(photos, 'Image Only!'), FileRequired('Choose a file!')])
    age = IntegerField('age', validators=[InputRequired(), NumberRange(0, 120)])
    gender = SelectField('gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[InputRequired()])
    submit = SubmitField('Upload')


class RegForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])


@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = generate_password_hash(form.password.data, method='sha256')
                hey = User(form.email.data, hashpass).save()
                login_user(hey)
                return redirect(url_for('upload_file'))
    return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('upload_file'))

    form = RegForm()
    wrong_password = False
    no_user = False
    if request.method == 'POST':
        if form.validate() or form.email.data == 'admin':
            # User.
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    flash('Logged in successfully.')
                    return redirect(url_for('upload_file'))
                else:
                    wrong_password = True
            else:
                no_user = True

    return render_template('index.html', form=form, wrong_password=wrong_password, no_user=no_user)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/show', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        for file in request.files.getlist('photo'):
            photos.save(file, folder=current_user.email, name=file.filename)
            Video(file_name=file.filename, email=current_user.email, age=form.age.data, gender=form.gender.data).save()
        success = True
    else:
        success = False
    return render_template('show.html', form=form, success=success, name=current_user.email)


@app.route('/manage')
def manage_file():
    files_list = []
    if current_user.email == 'admin':
        for email in os.listdir(app.config['UPLOADED_PHOTOS_DEST']):
            email_dir = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], email)
            if os.path.isdir(email_dir):
                for file in os.listdir(email_dir):
                    query_video = Video.objects(email=email, file_name=file).first()
                    files_list.append([file, email, query_video['age'], query_video['gender']])

    else:
        files = os.listdir(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], current_user.email))
        for file in files:
            query_video = Video.objects(email=current_user.email, file_name=file).first()
            files_list.append([file, current_user.email, query_video['age'], query_video['gender']])

    return render_template('manage.html', files_list=files_list, name=current_user.email)


@app.route('/open/<filename>')
def open_file(filename):
    file_url = photos.url(filename)
    return render_template('browser.html', file_url=file_url)


@app.route('/delete/<email>/<filename>')
def delete_file(filename, email):
    file_path = photos.path(os.path.join(email, filename))
    # file_path = photos.path(filename)
    os.remove(file_path)
    return redirect(url_for('manage_file'))


@app.route('/download/<email>/<filename>', methods=['GET', 'POST'])
def download_file(filename, email):
    file_path = os.path.join(app.config['UPLOADED_PHOTOS_DEST'], email)
    return send_from_directory(directory=file_path, filename=filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
