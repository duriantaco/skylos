import os
import sys
import argparse
import csv  # Unused import
from functools import wraps

from sample_repo import User, Product
from sample_repo import get_current_time

def register_commands():
    """Register CLI commands - used function."""
    parser = argparse.ArgumentParser(description='Sample CLI')
    subparsers = parser.add_subparsers(dest='command')
    
    user_parser = subparsers.add_parser('user', help='User commands')
    user_parser.add_argument('action', choices=['list', 'create'])
    
    product_parser = subparsers.add_parser('product', help='Product commands')
    product_parser.add_argument('action', choices=['list'])
    
    return parser

def handle_user_command(args):
    """Handle user command - used function."""
    if args.action == 'list':
        users = [
            User('john', 'john@example.com'),
            User('alice', 'alice@example.com')
        ]
        for user in users:
            print(f"User: {user.username} ({user.email})")
    elif args.action == 'create':
        user = User('new_user', 'new@example.com')
        print(f"Created user: {user.username} ({user.email})")

def handle_product_command(args):
    """Handle product command - used function."""
    if args.action == 'list':
        products = [
            Product('Laptop', 999.99),
            Product('Phone', 499.99)
        ]
        for product in products:
            print(f"Product: {product.name} - ${product.price:.2f}")

def export_data(data, filename):
    """Export data to CSV - unused function."""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'name', 'value'])
        for item in data:
            writer.writerow([item['id'], item['name'], item['value']])

def import_data(filename):
    """Import data from CSV - unused function."""
    data = []
    with open(filename, 'r', newline='') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            data.append({
                'id': row[0],
                'name': row[1],
                'value': row[2]
            })
    return data

class CommandDecorator:
    """Decorator for CLI commands - unused class."""
    
    def __init__(self, name, help_text):
        self.name = name
        self.help_text = help_text
    
    def __call__(self, func):
        """Call method - unused method."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            print(f"Executing command: {self.name}")
            return func(*args, **kwargs)
        return wrapper