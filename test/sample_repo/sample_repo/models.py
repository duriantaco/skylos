import datetime
import uuid
import hashlib  # Unused import
from typing import List, Dict, Optional

from .utils import get_current_time

class BaseModel:
    """Base model class with common functionality."""
    
    def __init__(self, id=None):
        self.id = id or str(uuid.uuid4())
        self.created_at = get_current_time()
    
    def to_dict(self):
        """Convert model to dictionary - used method."""
        return {
            'id': self.id,
            'created_at': self.created_at
        }
    
    def to_json(self):
        """Convert model to JSON - unused method."""
        import json
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data):
        """Create instance from dictionary - used method."""
        instance = cls(id=data.get('id'))
        if 'created_at' in data:
            instance.created_at = data['created_at']
        return instance

class User(BaseModel):
    """User model - used class."""
    
    def __init__(self, username, email, id=None):
        super().__init__(id)
        self.username = username
        self.email = email
        self.active = True
    
    def to_dict(self):
        """Override to_dict to include user fields - used method."""
        data = super().to_dict()
        data.update({
            'username': self.username,
            'email': self.email,
            'active': self.active
        })
        return data
    
    def deactivate(self):
        """Deactivate user - used method."""
        self.active = False
    
    def send_welcome_email(self):
        """Send welcome email - unused method."""
        pass

class Product(BaseModel):
    """Product model - used class."""
    
    def __init__(self, name, price, id=None):
        super().__init__(id)
        self.name = name
        self.price = price
    
    def to_dict(self):
        """Override to_dict for product - used method."""
        data = super().to_dict()
        data.update({
            'name': self.name,
            'price': self.price
        })
        return data
    
    def apply_discount(self, percentage):
        """Apply discount to product - unused method."""
        self.price = self.price * (1 - percentage / 100)

class Order(BaseModel):
    """Order model - unused class."""
    
    def __init__(self, user_id, products, id=None):
        super().__init__(id)
        self.user_id = user_id
        self.products = products
        self.status = 'pending'
    
    def to_dict(self):
        """Order to dict - unused method."""
        data = super().to_dict()
        data.update({
            'user_id': self.user_id,
            'products': self.products,
            'status': self.status
        })
        return data
    
    def complete(self):
        """Mark order as complete - unused method."""
        self.status = 'completed'

class Cart:
    """Shopping cart - unused class."""
    
    def __init__(self, user_id):
        self.user_id = user_id
        self.items = []
    
    def add_item(self, product_id, quantity=1):
        """Add item to cart - unused method."""
        self.items.append({
            'product_id': product_id,
            'quantity': quantity
        })
    
    def clear(self):
        """Clear cart - unused method."""
        self.items = []