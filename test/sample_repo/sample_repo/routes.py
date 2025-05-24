import os
import json
import logging
from functools import wraps

from sample_repo import User, Product
from sample_repo import format_currency

def require_auth(f):
    """Decorator to require authentication - used decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

def rate_limit(limit):
    """Decorator for rate limiting - unused decorator."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated
    return decorator

class App:
    """Simple application class - used class."""
    
    def __init__(self):
        self.routes = {}
        self.middlewares = []
        self._setup_routes()
    
    def _setup_routes(self):
        """Set up API routes - used method."""
        self.routes = {
            '/users': self.get_users,
            '/users/create': self.create_user,
            '/products': self.get_products
        }
    
    def add_middleware(self, middleware):
        """Add middleware - unused method."""
        self.middlewares.append(middleware)
    
    @require_auth
    def get_users(self):
        """Get users endpoint - used method."""
        users = [
            User('john', 'john@example.com'),
            User('alice', 'alice@example.com')
        ]
        return [user.to_dict() for user in users]
    
    def create_user(self):
        """Create user endpoint - used method."""
        user = User('new_user', 'new@example.com')
        return user.to_dict()
    
    def get_products(self):
        """Get products endpoint - used method."""
        products = [
            Product('Laptop', 999.99),
            Product('Phone', 499.99)
        ]
        return [
            {**product.to_dict(), 'formatted_price': format_currency(product.price)}
            for product in products
        ]
    
    @rate_limit(100)
    def get_analytics(self):
        """Get analytics endpoint - unused method."""
        return {'visits': 1000, 'unique_users': 500}
    
    def run(self):
        """Run the application - used method."""
        print("API server running...")

def create_app():
    """Create application - used function."""
    return App()

def parse_config(config_path):
    """Parse configuration file - unused function."""
    if not os.path.exists(config_path):
        return {}
    
    with open(config_path, 'r') as f:
        return json.load(f)
