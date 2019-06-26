# -*- coding: utf-8 -*-
import os
import time
import hashlib

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_mongoengine import MongoEngine, Document
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField
from wtforms import StringField, PasswordField
from wtforms.validators import Email, Length, InputRequired
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
patch_request_class(app)  # set maximum file size, default is 16MB


class User(UserMixin, db.Document):
    meta = {'collection': 'user_collection'}
    email = db.StringField(max_length=30)
    password = db.StringField()


class UploadForm(FlaskForm):
    photo = FileField(validators=[FileAllowed(photos, u'Image Only!'), FileRequired(u'Choose a file!')])
    submit = SubmitField(u'Upload')


@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()


class RegForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])


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
                return redirect(url_for('show'))
    return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated == True:
        return redirect(url_for('show'))
    form = RegForm()
    fail = False
    if request.method == 'POST':
        if form.validate() or form.email.data == 'admin':
            # User.
            check_user = User.objects(email=form.email.data).first()
            print(check_user)
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    flash('Logged in successfully.')
                    return redirect(url_for('show'))
        else:
            flash('Fail to login.')
            print('fail')
    return render_template('index.html', form=form)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/show', methods=['GET', 'POST'])
# @login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        for file in request.files.getlist('photo'):
            photos.save(file, name=file.filename)
        success = True
    else:
        success = False
    # return render_template('show.html', form=form, success=success, name=current_user.email)
    return render_template('show.html', form=form, success=success)


@app.route('/manage')
def manage_file():
    files_list = os.listdir(app.config['UPLOADED_PHOTOS_DEST'])
    return render_template('manage.html', files_list=files_list)


@app.route('/open/<filename>')
def open_file(filename):
    file_url = photos.url(filename)
    return render_template('browser.html', file_url=file_url)


@app.route('/delete/<filename>')
def delete_file(filename):
    file_path = photos.path(filename)
    os.remove(file_path)
    return redirect(url_for('manage_file'))


if __name__ == '__main__':
    app.run(debug=True)
