# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RemoveUser(FlaskForm):
    username = SelectField('Username', choices=[], coerce=int, validators=[DataRequired()])
    submit = SubmitField('Remove')

class MineForm(FlaskForm):
    type = SelectField('Sent/Received Tickets', validators=[DataRequired()])
    status = SelectField('Status', validators=[DataRequired()])
    submit = SubmitField('Search')

    def __init__(self, *args, **kwargs):
        super(MineForm, self).__init__(*args, **kwargs)
        self.status.choices = [(0, 'Processing'), (2, 'Rejected'), (1, 'End')]
        self.type.choices = [('sent', 'Sent'), ('received', 'Received')]

class All(FlaskForm):
    status = SelectField('Status', validators=[DataRequired()])
    submit = SubmitField('Search')

    def __init__(self, *args, **kwargs):
        super(All, self).__init__(*args, **kwargs)
        self.status.choices = [(0, 'Processing'), (2, 'Rejected'), (1, 'End')]


class TicketForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('File Name', validators=[DataRequired()])
    recipient = SelectField('Recipient', choices=[], coerce=int, validators=[DataRequired()])
    file = FileField('Upload PDF', validators=[DataRequired()])
    submit = SubmitField('Send Ticket')

    def __init__(self, *args, **kwargs):
        super(TicketForm, self).__init__(*args, **kwargs)
        self.recipient.choices = [(user.id, user.username) for user in User.query.all()]

# class ReplyForm(FlaskForm):
#     description = TextAreaField('Description', validators=[DataRequired()])
#     submit = SubmitField('Reply')

class ForwardForm(FlaskForm):
    recipient = SelectField('Forward To', choices=[], coerce=int, validators=[DataRequired()])
    description = StringField('File Name')
    file = FileField('Upload PDF')
    submit = SubmitField('Forward')

    def __init__(self, *args, **kwargs):
        super(ForwardForm, self).__init__(*args, **kwargs)
        self.recipient.choices = [(user.id, user.username) for user in User.query.all()]



