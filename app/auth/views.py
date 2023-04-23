from . import auth
from app.firestore_service import get_user, user_put
from app.models import UserData, UserModel
from app.forms import LoginForm
from flask import render_template, session, redirect, flash, url_for
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

@auth.route('/login', methods=['GET','POST'])
def login():

    if current_user.is_authenticated:
        flash('Ya estabas logueado')
        return redirect(url_for('index'))
    else:

        login_form = LoginForm()
        context = {
            'login_form':LoginForm()
        }

        if login_form.validate_on_submit():
            username = login_form.username.data
            password = login_form.password.data

            user_doc = get_user(username)

            if user_doc.to_dict() is not None:

                if check_password_hash(user_doc.to_dict()['password'], password):
                    user_data = UserData(username, password)
                    user = UserModel(user_data)

                    login_user(user)

                    flash('Bienvenido de nuevo')

                    redirect(url_for('hello'))
                elif password == user_doc.to_dict()['password']:
                    user_data = UserData(username, password)
                    user = UserModel(user_data)

                    login_user(user)

                    flash('Bienvenido de nuevo')
                else:
                    flash('La informacion proporcionada no coincide')
            else:
                flash('El Usuario no existe')

            return redirect(url_for('index'))

        return render_template('login.html', **context)
    
@auth.route('signup', methods=['GET', 'POST'])
def sign_up():
    signup_form = LoginForm()
    context = {
        'signup_form': signup_form
    }

    if signup_form.validate_on_submit():
        username = signup_form.username.data
        password = signup_form.password.data

        user_doc = get_user(username)

        if user_doc.to_dict() is None:
            password_hash = generate_password_hash(password)
            user_data = UserData(username, password_hash)
            user_put(user_data)

            user = UserModel(user_data)

            login_user(user)

            flash('Bienvenido')

            return redirect(url_for('hello'))
        else:
            flash('El usuario ya extiste')


    return render_template('signup.html', **context)

@auth.route('logout')
@login_required
def logout():
    logout_user()
    flash('Regresa pronto')

    return redirect(url_for('auth.login'))

