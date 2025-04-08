from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, FloatField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange, ValidationError
from .models import Race

class RaceForm(FlaskForm):
    name = StringField('Название заезда', validators=[DataRequired()])
    date = DateField('Дата заезда', format='%Y-%m-%d', validators=[DataRequired()])
    participant1 = StringField('Участник 1', validators=[DataRequired()])
    participant2 = StringField('Участник 2', validators=[DataRequired()])
    coefficient1 = FloatField('Коэффициент 1', validators=[DataRequired(), NumberRange(min=1.0)])
    coefficient2 = FloatField('Коэффициент 2', validators=[DataRequired(), NumberRange(min=1.0)])
    submit = SubmitField('Создать заезд')

class RegistrationForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=2, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтвердите пароль',
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

    def validate_name(self, field):
        if Race.query.filter_by(name=field.data).first():
            raise ValidationError('Заезд с таким названием уже существует')

class BetForm(FlaskForm):
    amount = FloatField('Сумма ставки', validators=[DataRequired(), NumberRange(min=0.01)])
    selected_participant = SelectField('Участник', choices=[], coerce=int)
    submit = SubmitField('Сделать ставку')

class DepositForm(FlaskForm):
    amount = FloatField('Сумма пополнения', validators=[
        DataRequired(),
        NumberRange(min=0.01, message="Сумма должна быть положительной")
    ])
    submit = SubmitField('Пополнить')