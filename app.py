from datetime import datetime, timedelta
from dotenv import load_dotenv
from logging import log
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (JWTManager, create_access_token, jwt_required, get_jwt_identity)
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, 'autocare.db')
load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-this-secret-in-prod')

# Token expires in 1 day 
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Models --- DB
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    logs = db.relationship('MaintenanceLog', backref='owner', cascade='all, delete-orphan')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'created_at': self.created_at.isoformat()
        }
        
class MaintenanceLog(db.Model):
    __tablename__ = 'maintenance_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    vehicle_make = db.Column(db.String(120), nullable=False)
    vehicle_model = db.Column(db.String(120), nullable=False)
    vehicle_year = db.Column(db.Integer, nullable=True)
    service_type = db.Column(db.String(120), nullable=False) 
    service_date = db.Column(db.Date, nullable=False)
    mileage = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'vehicle_make': self.vehicle_make,
            'vehicle_model': self.vehicle_model,
            'vehicle_year': self.vehicle_year,
            'service_type': self.service_type,
            'service_date': self.service_date.isoformat(),
            'mileage': self.mileage,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

# --- Helpers/Validators ---
def validate_registration_payload(payload):
    if not payload:
        return 'Missing JSON payload'
    username = payload.get('username')
    password = payload.get('password')
    if not username or not isinstance(username, str) or len(username) < 3:
        return 'username must be a string with at least 3 characters'
    if not password or not isinstance(password, str) or len(password) < 6:
        return 'password must be a string with at least 6 characters'
    return None 

def parse_date(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).date()
        except Exception:
# try common format yyyy-mm-dd
            try:
                return datetime.strptime(value, '%Y-%m-%d').date()
            except Exception:
                return None
    return None

def validate_log_payload(payload, for_update=False):
    if not payload:
        return 'Missing JSON payload'

    required_fields = ['vehicle_make', 'vehicle_model', 'service_type', 'service_date']
    if not for_update:
        for f in required_fields:
            if f not in payload:
                return f'Missing required field: {f}'
    # optional rani
    service_date = payload.get('service_date')
    if service_date:
        if not parse_date(service_date):
            return 'service_date must be a valid date (ISO 8601 or YYYY-MM-DD)'
    mileage = payload.get('mileage')
    if mileage is not None:
        try:
            int(mileage)
        except Exception:
            return 'mileage must be an integer if provided'
    return None

# -- Error Handlers ---
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad Request', 'message': getattr(e, 'description', str(e))}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Unauthorized', 'message': getattr(e, 'description', str(e))}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden', 'message': getattr(e, 'description', str(e))}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not Found', 'message': getattr(e, 'description', str(e))}), 404

@app.errorhandler(500)
def internal_err(e):
    return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred.'}), 500 

# --- Routes ---
@app.route('/register', methods=['POST'])
def register():
    payload = request.get_json()
    err = validate_registration_payload(payload)
    if err:
        abort(400, description=err)
    username = payload['username'].strip()
    password = payload['password']

    if User.query.filter_by(username=username).first():
        abort(400, description='Username already exists')

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'user': user.to_dict()}), 201

@app.route('/login', methods=['POST'])
def login():
    payload = request.get_json()
    if not payload:
        abort(400, description='Missing JSON payload')
    username = payload.get('username')
    password = payload.get('password')
    if not username or not password:
        abort(400, description='username and password are required')

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        abort(401, description='Invalid credentials')

    access_token = create_access_token(identity=str(user.id))
    return jsonify({'access_token': access_token, 'user': user.to_dict()}), 200

# Create a maintenance log
@app.route('/maintenance', methods=['POST'])
@jwt_required()
def create_log():
    user_id = int(get_jwt_identity())
    payload = request.get_json()
    err = validate_log_payload(payload)
    if err:
        abort(400, description=err)

    service_date = parse_date(payload.get('service_date'))

    log = MaintenanceLog(
        user_id=user_id,
        vehicle_make=payload.get('vehicle_make').strip(),
        vehicle_model=payload.get('vehicle_model').strip(),
        vehicle_year=payload.get('vehicle_year'),
        service_type=payload.get('service_type').strip(),
        service_date=service_date,
        mileage=payload.get('mileage'),
        notes=payload.get('notes')
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({'message': 'Maintenance log created', 'log': log.to_dict()}), 201   

# List authenticated user's logs
@app.route('/logs', methods=['GET'])
@jwt_required()
def list_logs():
    user_id = int(get_jwt_identity())
    # simple listing: newest first
    logs = MaintenanceLog.query.filter_by(user_id=user_id).order_by(MaintenanceLog.service_date.desc()).all()
    return jsonify({'logs': [l.to_dict() for l in logs]}), 200

# Update own log
@app.route('/logs/<int:log_id>', methods=['PUT'])
@jwt_required()
def update_log(log_id):
    user_id = int(get_jwt_identity())
    log = MaintenanceLog.query.get(log_id)
    if not log:
        abort(404, description='Log not found')
    if log.user_id != user_id:
        abort(403, description='Unauthorized access to this log')
        
    payload = request.get_json()
    err = validate_log_payload(payload, for_update=True)
    if err:
        abort(400, description=err)

    # update fields if provided
    if 'vehicle_make' in payload:
        log.vehicle_make = payload.get('vehicle_make').strip()
    if 'vehicle_model' in payload:
        log.vehicle_model = payload.get('vehicle_model').strip()
    if 'vehicle_year' in payload:
        log.vehicle_year = payload.get('vehicle_year')
    if 'service_type' in payload:
        log.service_type = payload.get('service_type').strip()
    if 'service_date' in payload:
        sd = parse_date(payload.get('service_date'))
        if not sd:
            abort(400, description='service_date must be a valid date')
        log.service_date = sd
    if 'mileage' in payload:
        log.mileage = payload.get('mileage')
    if 'notes' in payload:
        log.notes = payload.get('notes')

    db.session.commit()
    return jsonify({'message': 'Log updated', 'log': log.to_dict()}), 200

# Delete own log
@app.route('/logs/<int:log_id>', methods=['DELETE'])
@jwt_required()
def delete_log(log_id):
    user_id = int(get_jwt_identity()) 
    log = MaintenanceLog.query.get(log_id)
    if not log:
        abort(404, description='Log not found')
    if log.user_id != user_id:
        abort(403, description='Unauthorized access to this log')

    db.session.delete(log)
    db.session.commit()
    return jsonify({'message': 'Log deleted'}), 200

@app.route('/reset-db', methods=['POST'])
def reset_db():
    from flask import current_app
    with current_app.app_context():
        db.drop_all()   
        db.create_all() 
    return jsonify({"msg": "Database reset successfully"}), 200

# Health check and DB init
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'all goods runnable'}), 200

def init_db():
    with app.app_context():
        if not os.path.exists(db_path):
            db.create_all()
            print('Database created at {}'.format(db_path))
        else:
            print('Database already exists at {}'.format(db_path))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)