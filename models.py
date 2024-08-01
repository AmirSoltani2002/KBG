from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.types import JSON
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    # Add other fields as necessary

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Sender
    recipient_ids = db.Column(MutableList.as_mutable(JSON), nullable=False)
    status = db.Column(db.Integer, default=0)  # -1: Rejected, 0: Not checked, 1: Checked
    file_path = db.Column(db.String(200), nullable=True)  # Add this field to store file path
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[user_id], backref='sent_tickets')
    recipients = db.relationship('User', secondary='ticket_recipient', backref='received_tickets')

ticket_recipient = db.Table('ticket_recipient',
    db.Column('ticket_id', db.Integer, db.ForeignKey('ticket.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# Ensure to create migrations and apply them

