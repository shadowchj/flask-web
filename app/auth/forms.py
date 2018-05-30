from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User

#如果表单类中定义了以validate_开头且后面跟着字段名的方法，这个方法就和常规的验证函数一起调用

class LoginForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    remember_me = BooleanField('保持登陆状态')
    submit = SubmitField('登陆')


class RegistrationForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('用户名', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[_A-Za-z\u4e00-\u9fa5]*$', 0,
               '用户名只能由中文，字母，下划线组成')])
    password = PasswordField('密码', validators=[DataRequired(), Length(8, message='密码长度不能小于8位'), 
        EqualTo('password2', message='两次输入密码不一样！')])
    password2 = PasswordField('确认密码', validators=[DataRequired()])
    submit = SubmitField('注册')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('邮箱已经被注册了！.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名已经存在！.')



class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('原密码', validators=[DataRequired()])
    password = PasswordField('新密码', validators=[Length(8, message='密码长度不能小于8位'),
        DataRequired(), EqualTo('password2', message='两次输入密码不一样！')])
    password2 = PasswordField('确认新密码',
                              validators=[DataRequired()])
    submit = SubmitField('确认提交')



class PasswordResetForm(FlaskForm):
    email = StringField('登陆账号/邮箱', validators=[DataRequired(), Length(1, 64),Email()])
    password = PasswordField('新密码', validators=[Length(8, message='密码长度不能小于8位'),
        DataRequired(), EqualTo('password2', message='两次输入密码不一样！')])
    password2 = PasswordField('确认新密码', validators=[DataRequired()])
    submit = SubmitField('重置密码')


class ChangeEmailForm(FlaskForm):
    email = StringField('新邮箱地址', validators=[DataRequired(), Length(1, 64),
                                                 Email(message='邮箱格式不正确')])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('确认提交')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('新邮箱已经被注册了！')
