from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, \
    current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm,\
    PasswordResetForm, ChangeEmailForm

'''flask_login:login_required修饰器保护路由，只有认证过的用户才能访问，未认证的会被拦截，并转到
   登陆页面（loginManager.login_view中设置的路由）
   login_user()参数为要登陆的用户（在用户会话中把用户标记为已登陆）以及可选的"记住我"布尔值,True
   则会写入有效期的cookie，可以复现用户会话session，false则不记住，关闭后用户会话过期
   logout_user()删除并重设用户会话
   current_user在视图函数和模板中都自动可用，值为当前登陆的用户（实例），如未登录则为匿名用户，is_authenticated
   方法将返回False；在Login_user之后可使用'''



#登陆界面
@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('用户名或者密码不正确！')
    return render_template('auth/login.html', form=form)

#登出界面
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('你已经成功登出账户！')
    return redirect(url_for('main.index'))

#注册界面
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('已成功注册账号！')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


#改变密码
@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('成功更改密码！')
            return redirect(url_for('main.index'))
        else:
            flash('原密码输入错误！')
    return render_template("auth/change_password.html", form=form)


#重置密码
@auth.route('/reset', methods=['GET', 'POST'])
def password_reset():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(form.email.data, form.password.data):
            db.session.commit()
            flash('密码已重置！')
            return redirect(url_for('auth.login'))
        else:
            flash('该用户不存在！')
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)

#改变邮箱
@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            current_user.change_email(new_email)
            db.session.commit()
            flash('邮箱已更改')
            return redirect(url_for('main.index'))
        else:
            flash('密码输入错误')
    return render_template("auth/change_email.html", form=form)

