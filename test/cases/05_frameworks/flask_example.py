from flask import Flask, request, jsonify, render_template, redirect, url_for
from functools import wraps
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/users', methods=['GET'])
def get_users():
    """used"""
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/api/users', methods=['POST'])
def create_user():
    """create a new user"""
    data = request.get_json()
    user = User(name=data['name'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return '', 204

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# these 3 below i.e. old legacy, secret and exp should be detected as dead code
@app.route('/api/legacy/old_endpoint')
def old_legacy_endpoint():
    """DEAD CODE"""
    return jsonify({'message': 'This is old and unused'})

@app.route('/admin/secret', methods=['GET', 'POST'])
@admin_required
def secret_admin_page():
    if request.method == 'POST':
        pass
    return render_template('secret.html')

@app.route('/api/experimental/<string:feature>')
def experimental_feature(feature):
    return jsonify({'feature': feature, 'status': 'experimental'})

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

def validate_user_data(data):
    """USED"""
    required_fields = ['name', 'email']
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
    return True

def send_welcome_email(user):
    """USED"""
    logger.info(f"Sending welcome email to {user.email}")
    return True

def format_user_display_name(user):
    """UNUSED HELPER"""
    return f"{user.first_name} {user.last_name}".strip()

def calculate_user_stats(user_id):
    """UNUSED"""
    user = User.query.get(user_id)
    if not user:
        return None
    
    stats = {
        'login_count': 0,
        'last_login': None,
        'total_posts': 0
    }
    return stats

def generate_api_key():
    """UNUSED"""
    import secrets
    return secrets.token_urlsafe(32)

@app.before_request
def before_request():
    logger.info(f"Request: {request.method} {request.path}")

@app.after_request
def after_request(response):
    """Add CORS """
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.before_first_request
def initialize_database():
    """NEVER CALLED"""
    pass

@app.teardown_appcontext
def close_database(error):
    """UNUSED"""
    pass

def create_app(config_name=None):
    """DEAD CODE"""
    app = Flask(__name__)
    
    if config_name:
        app.config.from_object(config_name)
    
    return app

if __name__ == '__main__':
    app.run(debug=True)