from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    verdict = db.Column(db.String(50))
    flags = db.Column(db.Text)          # JSON string of flags
    screenshot_url = db.Column(db.String(500))
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Scan {self.url} — {self.verdict}>"