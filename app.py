import os
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
from openai import OpenAI
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text, desc
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
import stripe
import logging

# --- INITIAL CONFIGURATION ---
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": "*"}})

# --- SECURITY AND JWT CONFIGURATION ---
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "a-super-secret-key-for-development-only")
jwt = JWTManager(app)

# --- STRIPE CONFIGURATION ---
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
stripe_webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

# --- DATABASE CONFIGURATION ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is not set.")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- LOGGING ---
logging.basicConfig(level=logging.INFO)

# --- DATABASE MODELS (Multi-Tenant Architecture) ---

class User(db.Model):
    """Represents the restaurant owner."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    stripe_customer_id = db.Column(db.String(120), unique=True, nullable=True)
    restaurant = db.relationship('Restaurant', back_populates='owner', uselist=False, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Restaurant(db.Model):
    """Represents a tenant in the system."""
    __tablename__ = 'restaurants'
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    logo_url = db.Column(db.String(255), nullable=True)
    review_platform_url = db.Column(db.String(255), nullable=True, default="https://www.google.com")
    subscription_plan = db.Column(db.String(50), nullable=True)
    subscription_status = db.Column(db.String(50), default='incomplete')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', back_populates='restaurant')
    servers = db.relationship('Server', backref='restaurant', lazy=True, cascade="all, delete-orphan")
    dishes = db.relationship('Dish', backref='restaurant', lazy=True, cascade="all, delete-orphan")
    reviews = db.relationship('GeneratedReview', backref='restaurant', lazy=True, cascade="all, delete-orphan")
    language_settings = db.relationship('LanguageSetting', backref='restaurant', lazy=True, cascade="all, delete-orphan")

class LanguageSetting(db.Model):
    __tablename__ = 'language_settings'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurants.id'), nullable=False)
    language_code = db.Column(db.String(5), nullable=False) # e.g., 'fr', 'en'
    is_enabled = db.Column(db.Boolean, default=True)
    __table_args__ = (db.UniqueConstraint('restaurant_id', 'language_code', name='_restaurant_language_uc'),)

class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurants.id'), nullable=False)
    name = db.Column(db.String(80), nullable=False)

class Dish(db.Model):
    """Replaces FlavorOption."""
    __tablename__ = 'dishes'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurants.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)

class GeneratedReview(db.Model):
    """Logs generated reviews."""
    __tablename__ = 'generated_reviews'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurants.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Potentially add more fields like the generated text, language, etc.

# Other models like MenuSelection, InternalFeedback, QualitativeFeedback would also be updated
# with a mandatory `restaurant_id` foreign key.

# --- BLUEPRINTS (Code Organization) ---
from flask import Blueprint

# Public API (no auth needed)
public_bp = Blueprint('public', __name__, url_prefix='/api/public')

# Authentication
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Dashboard API (JWT required)
dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

# Webhooks (from Stripe, etc.)
webhooks_bp = Blueprint('webhooks', __name__, url_prefix='/api/webhooks')


# --- PUBLIC API ROUTES ---
@public_bp.route('/config/<string:slug>')
def get_restaurant_config(slug):
    """
    Returns the public configuration for a restaurant page.
    This is what the customer-facing review page will call.
    """
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()

    if restaurant.subscription_status != 'active':
        return jsonify({"error": "This page is not available."}), 404

    servers = Server.query.filter_by(restaurant_id=restaurant.id).order_by(Server.name).all()
    dishes = Dish.query.filter_by(restaurant_id=restaurant.id).all()
    
    dishes_by_category = {}
    for dish in dishes:
        if dish.category not in dishes_by_category:
            dishes_by_category[dish.category] = []
        dishes_by_category[dish.category].append({"id": dish.id, "name": dish.name})

    # Add language settings logic here
    languages = LanguageSetting.query.filter_by(restaurant_id=restaurant.id, is_enabled=True).all()
    
    config = {
        "restaurant_name": restaurant.name,
        "logo_url": restaurant.logo_url,
        "review_platform_url": restaurant.review_platform_url,
        "servers": [{"id": s.id, "name": s.name} for s in servers],
        "dishes": dishes_by_category,
        "languages": [{"code": lang.language_code, "is_enabled": lang.is_enabled} for lang in languages]
    }
    return jsonify(config)

# --- AUTHENTICATION ROUTES ---
@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Registers a new user and creates an associated restaurant.
    This is the first step of the onboarding.
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    restaurant_name = data.get('restaurant_name')

    if not all([email, password, restaurant_name]):
        return jsonify({"error": "Missing required fields"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    # Create Stripe Customer
    try:
        customer = stripe.Customer.create(
            email=email,
            name=restaurant_name,
        )
    except Exception as e:
        logging.error(f"Stripe customer creation failed: {e}")
        return jsonify({"error": "Could not create payment profile."}), 500

    # Create User and Restaurant
    new_user = User(email=email, stripe_customer_id=customer.id)
    new_user.set_password(password)
    
    new_restaurant = Restaurant(
        name=restaurant_name,
        # Generate a simple slug, needs improvement for production
        slug=f"{restaurant_name.lower().replace(' ', '-')}-{os.urandom(3).hex()}",
        owner=new_user
    )

    db.session.add(new_user)
    db.session.add(new_restaurant)
    db.session.commit()
    
    # Create default language settings
    default_langs = ['fr', 'en', 'es', 'it']
    for lang_code in default_langs:
        lang_setting = LanguageSetting(restaurant_id=new_restaurant.id, language_code=lang_code, is_enabled=True)
        db.session.add(lang_setting)
    db.session.commit()

    return jsonify({
        "message": "User registered successfully.",
        "user_id": new_user.id,
        "restaurant_id": new_restaurant.id,
        "stripe_customer_id": new_user.stripe_customer_id
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """Logs in a user and returns a JWT."""
    data = request.get_json()
    email = data.get("email", None)
    password = data.get("password", None)
    
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        # The identity of the token contains the user ID and their restaurant ID
        identity = {"user_id": user.id, "restaurant_id": user.restaurant.id}
        access_token = create_access_token(identity=identity)
        return jsonify(access_token=access_token)
        
    return jsonify({"msg": "Bad email or password"}), 401


@auth_bp.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    """
    Creates a Stripe Checkout session for subscribing to a plan.
    """
    data = request.get_json()
    price_id = data.get('price_id') # e.g., price_1PABCDE...
    
    current_user_identity = get_jwt_identity()
    user = db.session.get(User, current_user_identity['user_id'])

    if not user or not user.stripe_customer_id:
        return jsonify({"error": "User or payment profile not found."}), 404

    try:
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            success_url=request.json.get('success_url', 'http://localhost:5000/success'), # Should be frontend URL
            cancel_url=request.json.get('cancel_url', 'http://localhost:5000/cancel'), # Should be frontend URL
            # Pass restaurant_id to identify the tenant upon webhook reception
            subscription_data={
                "metadata": {
                    'restaurant_id': user.restaurant.id
                }
            }
        )
        return jsonify({'sessionId': checkout_session.id, 'url': checkout_session.url})
    except Exception as e:
        logging.error(f"Stripe checkout session creation failed: {e}")
        return jsonify({'error': str(e)}), 500


# --- DASHBOARD API ROUTES (Secured) ---
@dashboard_bp.route('/stats')
@jwt_required()
def dashboard_stats():
    """
    Returns stats for the logged-in user's restaurant.
    All queries are automatically filtered by restaurant_id.
    """
    identity = get_jwt_identity()
    restaurant_id = identity['restaurant_id']
    
    # Example: Count reviews for this restaurant
    review_count = GeneratedReview.query.filter_by(restaurant_id=restaurant_id).count()
    
    return jsonify({
        "restaurant_id": restaurant_id,
        "total_reviews": review_count,
        "message": "More stats to come!"
    })

# CRUD for Servers
@dashboard_bp.route('/servers', methods=['GET', 'POST'])
@jwt_required()
def manage_servers():
    identity = get_jwt_identity()
    restaurant_id = identity['restaurant_id']

    if request.method == 'POST':
        data = request.get_json()
        if not data or not data.get('name'):
            return jsonify({"error": "Name is required"}), 400
        new_server = Server(name=data['name'].strip(), restaurant_id=restaurant_id)
        db.session.add(new_server)
        db.session.commit()
        return jsonify({"id": new_server.id, "name": new_server.name}), 201

    servers = Server.query.filter_by(restaurant_id=restaurant_id).order_by(Server.name).all()
    return jsonify([{"id": s.id, "name": s.name} for s in servers])

# ... other CRUD endpoints for dishes, settings, etc. would follow a similar pattern ...


# --- WEBHOOK ROUTES ---
@webhooks_bp.route('/stripe', methods=['POST'])
def stripe_webhook():
    """
    Listens for events from Stripe to manage subscription status.
    """
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return 'Invalid signature', 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        # This is where you'd fulfill the purchase
        # For subscriptions, the `customer.subscription.created` event is often more useful
        logging.info(f"Checkout session completed for session ID: {session.id}")

    if event['type'] in ['customer.subscription.created', 'customer.subscription.updated']:
        subscription = event['data']['object']
        restaurant_id = subscription['metadata'].get('restaurant_id')
        if restaurant_id:
            restaurant = db.session.get(Restaurant, restaurant_id)
            if restaurant:
                restaurant.subscription_status = subscription['status'] # e.g., 'active', 'past_due'
                # You might also want to store the plan name
                restaurant.subscription_plan = subscription['items']['data'][0]['price']['lookup_key'] # if you use lookup_keys
                db.session.commit()
                logging.info(f"Subscription for restaurant {restaurant_id} updated to {subscription['status']}")

    if event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        restaurant_id = subscription['metadata'].get('restaurant_id')
        if restaurant_id:
            restaurant = db.session.get(Restaurant, restaurant_id)
            if restaurant:
                restaurant.subscription_status = 'canceled'
                db.session.commit()
                logging.info(f"Subscription for restaurant {restaurant_id} canceled.")

    return 'Success', 200


# --- REGISTER BLUEPRINTS ---
app.register_blueprint(public_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(webhooks_bp)

# --- DATABASE CREATION & MAIN EXECUTION ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5001)
