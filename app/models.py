from .extensions import db
from datetime import datetime
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Numeric(10, 2), default=Decimal('0.00'))
    bets = db.relationship('Bet', backref='user', lazy=True)

class Race(db.Model):
    __tablename__ = 'races'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    date = db.Column(db.DateTime, nullable=False)
    participant1 = db.Column(db.String(80), nullable=False)
    participant2 = db.Column(db.String(80), nullable=False)
    coefficient1 = db.Column(db.Numeric(5, 2), nullable=False)
    coefficient2 = db.Column(db.Numeric(5, 2), nullable=False)
    is_finished = db.Column(db.Boolean, default=False)
    winner = db.Column(db.Integer)
    bets = db.relationship('Bet', backref='race', lazy=True)

    def calculate_winnings(self, participant):
        try:
            if participant == 1:
                return self.coefficient1
            return self.coefficient2
        except Exception as e:
            logger.error(f"Error calculating winnings: {str(e)}")
            return Decimal('1.0')

class Bet(db.Model):
    __tablename__ = 'bets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    race_id = db.Column(db.Integer, db.ForeignKey('races.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    selected_participant = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)