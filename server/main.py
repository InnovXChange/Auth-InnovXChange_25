import os
from dotenv import load_dotenv
import secrets
import requests
from uuid import uuid4
from datetime import datetime, timedelta
from pymongo import MongoClient
from flask_session import Session
from flask import Flask, request, jsonify, render_template, redirect, url_for, session

# Load environment variables from .env file
load_dotenv()

# Constants
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAIL_URL = "https://api.github.com/user/emails"
MAX_EMAIL_VERIFICATION_ATTEMPTS = 5
EMAIL_CODE_EXPIRY_HOURS = 24

# Initialize Flask application
app = Flask(__name__)

# MongoDB setup
mongo_client = MongoClient(os.environ['MONGODB_CONNECTION_STRING'])
user_collection = mongo_client['user_accounts']['users']
verification_collection = mongo_client['email_verification']['email_verification_codes']

# Configure session handling with MongoDB
app.config.update(
    SESSION_TYPE='mongodb',
    SESSION_MONGODB=mongo_client,
    SESSION_MONGODB_DB='user_sessions',
    SESSION_MONGODB_COLLECTION='sessions',
    SESSION_COOKIE_NAME='X-IDENTIFIER',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
Session(app)

# Helper Functions
def generate_github_url(state):
    """
    Generate GitHub OAuth URL with necessary query parameters.
    
    Args:
        state (str): A unique state token to prevent CSRF attacks.
    
    Returns:
        str: A URL to initiate GitHub OAuth login.
    """
    return f"{GITHUB_AUTH_URL}?client_id={os.environ['GITHUB_CLIENT_ID']}&redirect_uri={os.environ['BASE_REDIRECT_URI']}/api/v1/oauth/github/callback&scope=user:email&state={state}&allow_signup=true"

def fetch_github_user(access_token):
    """
    Fetch GitHub user data using the access token.
    
    Args:
        access_token (str): GitHub access token.
    
    Returns:
        dict: GitHub user data or error message if the token is invalid.
    """
    response = requests.get(GITHUB_USER_URL, headers={'Authorization': f'token {access_token}'})
    if response.status_code == 401:
        return jsonify({'error': 'Invalid access token, please try again.'})
    return response.json()

def fetch_github_user_email(access_token):
    """
    Fetch the primary email of the GitHub user.
    
    Args:
        access_token (str): GitHub access token.
    
    Returns:
        str: The primary email of the user, or None if not found.
    """
    response = requests.get(GITHUB_EMAIL_URL, headers={'Authorization': f'token {access_token}'})
    response.raise_for_status()
    emails = response.json()
    return next((email['email'] for email in emails if email.get('primary')), None)

def validate_email_format(email):
    """
    Validate the format of an email address.
    
    Args:
        email (str): The email address to be validated.
    
    Returns:
        bool: True if the email format is valid, False otherwise.
    """
    return '@' in email and '.' in email and ' ' not in email


# Middleware
@app.after_request
def application_metrics(response):
    """
    Middleware to log application metrics for each request.
    
    Args:
        response (Response): The response object for the request.
    
    Returns:
        Response: The response object with metrics logged.
    """
    mongo_client['application_metrics']['request_logs'].insert_one({
        'timestamp': datetime.now(),
        'method': request.method,
        'path': request.path,
        'status_code': response.status_code,
        'remote_address': request.remote_addr
    })

    return response

# Routes
@app.route('/')
def home():
    """
    Home route to handle authenticated and unauthenticated users.
    
    Returns:
        str: Rendered HTML template based on user session.
    """
    if 'user' in session:
        return render_template('redirect-authenticated_user.html')
    return render_template('authentication.html')

@app.route('/api/v1/oauth/github/initiate', methods=['GET'])
def initiate_github_login():
    """
    Initiate GitHub OAuth login process.
    
    Returns:
        Response: Redirect to GitHub login page with authorization URL.
    """
    if 'user' in session:
        return redirect(url_for('home'))

    state = secrets.token_urlsafe(32)
    session['github_auth_request_state'] = state
    return redirect(generate_github_url(state))

@app.route('/api/v1/oauth/github/callback', methods=['GET'])
def github_login_callback():
    """
    Handle GitHub OAuth callback after the user grants authorization.
    
    Returns:
        Response: A JSON response or redirection based on success or error.
    """
    if request.args.get('state') != session.get('github_auth_request_state'):
        return jsonify({'error': 'State mismatch. Please try again.'})

    if request.args.get('error'):
        return jsonify({'error': request.args.get('error_description').replace('+', ' ').capitalize()})

    # Exchange code for token
    response = requests.post(GITHUB_TOKEN_URL, headers={'Accept': 'application/json'}, data={
        'client_id': os.environ['GITHUB_CLIENT_ID'],
        'client_secret': os.environ['GITHUB_CLIENT_SECRET'],
        'code': request.args.get('code')
    })
    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch access token. Please try again later.'})
    access_token = response.json().get('access_token')

    # Fetch user data from GitHub
    github_user = fetch_github_user(access_token)
    github_user['email'] = github_user.get('email') or fetch_github_user_email(access_token)

    # Check if the user is registered
    user = user_collection.find_one({'user_account.user_github_username': github_user['login'].lower()})
    if not user:
        return jsonify({
            'status': 'error',
            'message': f"The user @{github_user['login'].lower()} is not yet registered for the InnovXChange Hackathon. If you have already registered, please join the WhatsApp group at https://chat.whatsapp.com/HGdWefCBxhaHgVcCbyn3Xc for further assistance."
      })

    # Set user session
    session['user'] = {
        'user_public_id': user['user_public_id'],
        'user_display_name': user['user_profile']['user_display_name'],
        'user_roles': user['user_account']['user_roles']
    }
    return redirect(url_for('home'), code=302)

@app.route('/email-verification')
def email_verification():
    """
    Display the email verification page.
    
    Returns:
        str: Rendered email verification template.
    """
    if 'user' in session:
        return redirect(url_for('home'))
    if not request.args.get('email') or not request.args.get('identifier'):
        return redirect(url_for('home'))
    return render_template('email-verification.html', email=request.args.get('email'), identifier=request.args.get('identifier'))

@app.route('/api/v1/email/send-login-code', methods=['POST'])
def send_login_code():
    """
    Send a one-time login code to the user's email address.
    
    Returns:
        Response: JSON response with the status of the operation.
    """
    email = request.json.get('email', '').lower()
    if not validate_email_format(email):
        return jsonify({'status': 'error', 'message': 'Invalid email address, please try again.'})

    user = user_collection.find_one({'user_profile.user_email': email})
    if not user:
        return jsonify({'status': 'error', 'message': f"The email {email} is not yet registered for the InnovXChange Hackathon. If you have already registered, please join the WhatsApp group at https://chat.whatsapp.com/HGdWefCBxhaHgVcCbyn3Xc for further assistance.", 'destination': 'https://chat.whatsapp.com/HGdWefCBxhaHgVcCbyn3Xc'})

    attempts = verification_collection.count_documents({
        'email': email, 
        'created_at': {'$gte': datetime.now() - timedelta(hours=EMAIL_CODE_EXPIRY_HOURS)}
    })
    if attempts >= MAX_EMAIL_VERIFICATION_ATTEMPTS:
        return jsonify({'status': 'error', 'message': 'Max verification attempts reached. Try later.'})

    # Generate and store verification code
    code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(6))
    identifier = uuid4().hex
    verification_collection.insert_one({
        'identifier': identifier, 'email': email, 'code': code, 'created_at': datetime.now()
    })

    # Simulated email (Replace with actual email sending logic)
    print(f"Verification code for {email}: {code}")
    return jsonify({'status': 'success', 'identifier': identifier, 'email': email})

@app.route('/api/v1/authentication/verify-code', methods=['POST'])
def verify_code():
    """
    Verify the one-time login code.
    
    Returns:
        Response: JSON response with verification result.
    """
    data = request.json
    identifier = data.get('identifier', '')
    code = data.get('code', '').upper()

    if not identifier or not code:
        return jsonify({'status': 'error', 'message': 'Identifier and code are required.'}), 400

    # Fetch the verification record
    verification_record = verification_collection.find_one({'identifier': identifier})

    if not verification_record:
        return jsonify({'status': 'error', 'message': 'Invalid identifier or code.'}), 404

    # Check if the code is expired
    if verification_record['created_at'] + timedelta(hours=EMAIL_CODE_EXPIRY_HOURS) < datetime.now():
        return jsonify({'status': 'error', 'message': 'The code has expired. Please request a new one to continue.'}), 401

    # Check if the code matches
    if verification_record['code'] != code:
        return jsonify({'status': 'error', 'message': 'The code is incorrect. Please try again or request a new one.'}), 401

    # Fetch the user by email
    email = verification_record['email']
    user = user_collection.find_one({'user_profile.user_email': email})
    if not user:
        return jsonify({'status': 'error', 'message': f"The email {email} is not yet registered for the InnovXChange Hackathon. If you have already registered, please join the WhatsApp group at https://chat.whatsapp.com/HGdWefCBxhaHgVcCbyn3Xc for further assistance.", 'destination': 'https://chat.whatsapp.com/HGdWefCBxhaHgVcCbyn3Xc'})

    # Successful verification
    session['user'] = {
        'user_public_id': user['user_public_id'],
        'user_display_name': user['user_profile']['user_display_name'],
        'user_roles': user['user_account']['user_roles']
    }

    verification_collection.delete_one({'identifier': identifier})

    return jsonify({
        'status': 'success',
        'message': 'Verification successful.',
        'user': {
            'public_id': user['user_public_id'],
            'display_name': user['user_profile']['user_display_name'],
            'roles': user['user_account']['user_roles']
        }
    })

@app.route('/api/v1/logout', methods=['GET'])
def logout():
    """
    Log out the user and clear session data.
    
    Returns:
        Response: Redirect to home after logging out.
    """
    session.pop('user', None)
    return redirect(url_for('home'))


# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    """
    Custom error handler for 404 page not found error.
    
    Returns:
        Response: JSON response indicating resource was not found.
    """
    return jsonify({'error': 'The requested resource was not found on the server.'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    """
    Custom error handler for 500 internal server error.
    
    Returns:
        Response: JSON response indicating an internal server error.
    """
    return jsonify({'error': 'An internal server error occurred. Please try again later.'}), 500

# Utility Routes
@app.route('/favicon.ico')
def favicon():
    """
    Route for favicon redirection.
    
    Returns:
        Response: Redirect to favicon image URL.
    """
    return redirect("https://cdn.innovxchange.in/assets/images/favicon.ico")

# Run the application
if __name__ == '__main__':
    app.run(port=os.environ.get('PORT', 5050), debug=os.environ.get('ENVIROMENT') == 'development')
