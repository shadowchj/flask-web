from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField,\
    SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp
from wtforms import ValidationError
from flask_pagedown.fields import PageDownField
from ..models import Role, User

#如果表单类中定义了以validate_开头且后面跟着字段名的方法，这个方法就和常规的验证函数一起调用


class NameForm(FlaskForm):
    name = StringField('请输入你的姓名', validators=[DataRequired()])
    submit = SubmitField('提交')


#普通用户资料编辑表单
class EditProfileForm(FlaskForm):
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('位置', validators=[Length(0, 64)])
    about_me = TextAreaField('关于我')
    submit = SubmitField('提交修改')

#管理员资料编辑表单
class EditProfileAdminForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('用户名', validators=[
        DataRequired(), Length(1, 64),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
               'Usernames must have only letters, numbers, dots or '
               'underscores')])
    #SelectField是表单控件<select>的包装，实现下拉列表，实例为其choices属性中设置的各选项(必须是元组组成的列表)
    #各个元组包含两个元素：选项的标识符和显示在控件中的文本字符串，Coerce=Int初始设置把字段值变成整数
    role = SelectField('权限', coerce=int)
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('位置', validators=[Length(0, 64)])
    about_me = TextAreaField('关于我')
    submit = SubmitField('提交修改')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

#编写博客表单
class PostForm(FlaskForm):
    title = StringField("标题", validators=[DataRequired()])
    summary = TextAreaField('内容概括', validators=[DataRequired()])
    body = PageDownField("你想写点什么?(支持markdown格式)", validators=[DataRequired()])
    submit = SubmitField('提交')

#编写评论表单
class CommentForm(FlaskForm):
    body = StringField('发表一下你的评论吧...', validators=[DataRequired()])
    submit = SubmitField('发表')
