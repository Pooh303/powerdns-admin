from datetime import datetime
from .base import db

class ServerHealth(db.Model):
    __tablename__ = 'server_health'
    
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'healthy' or 'unhealthy'
    last_check = db.Column(db.DateTime, nullable=False)
    details = db.Column(db.JSON)
    
    def __init__(self, server_id):
        self.server_id = server_id
        self.status = 'unknown'
        self.last_check = datetime.utcnow()
        self.details = {}
        
    def to_dict(self):
        return {
            'id': self.id,
            'server_id': self.server_id,
            'status': self.status,
            'last_check': self.last_check.isoformat(),
            'details': self.details
        } 