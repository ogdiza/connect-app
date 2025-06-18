import os
import google.oauth2.credentials
from google_auth_oauthlib.flow import Flow # Use this for the web login flow
from googleads import ad_manager, oauth2   # Use this for the API calls
from flask import Flask, render_template, session, redirect, url_for, request
from dotenv import load_dotenv
from datetime import date # Import the date module

# Load environment variables from .env file
load_dotenv()

# --- App Configuration ---
app = Flask(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# --- Google OAuth Configuration ---
CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = os.getenv('https://connect-app-np6z.onrender.com/callback')

SCOPES = [
    'https://www.googleapis.com/auth/admanager',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'openid'
]

# --- Helper Function ---
def credentials_to_dict(credentials):
    """Converts Google credentials object to a dictionary for session storage."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

# --- Routes ---

@app.route('/')
def home():
    """The main dashboard page."""
    if 'credentials' not in session:
        return redirect(url_for('login'))

    user_info = session.get('user_info', {})
    today_date = date.today().strftime("%Y-%m-%d")

    # Check if we have the user's network code stored.
    if 'network_code' not in session:
        # If not, show the setup page asking the user to enter it.
        return render_template('index.html', needs_network_code=True, user_email=user_info.get('email'))

    # If we DO have the network code, proceed to fetch API data.
    try:
        oauth2_client = oauth2.GoogleRefreshTokenClient(
            CLIENT_ID, CLIENT_SECRET, session['credentials']['refresh_token'])

        ad_manager_client = ad_manager.AdManagerClient(
            oauth2_client, 'Connect App', network_code=session['network_code'])

        network_service = ad_manager_client.GetService('NetworkService')
        
        current_network = network_service.getCurrentNetwork()
        parent_network_code = current_network['networkCode']
        
        statement = ad_manager.StatementBuilder()
        all_networks = network_service.getAllNetworks()
        
        child_networks = []
        if all_networks:
            child_networks = [
                network for network in all_networks
                if network['networkCode'] != parent_network_code
            ]

        return render_template(
            'index.html',
            user_email=user_info.get('email'),
            current_network=current_network,
            child_networks=child_networks,
            today_date=today_date
        )
    
    except Exception as e:
        return render_template('index.html', error=str(e), user_email=user_info.get('email'), today_date=today_date)


@app.route('/save_network_code', methods=['POST'])
def save_network_code():
    """Saves the user-submitted network code to the session."""
    if 'credentials' not in session:
        return redirect(url_for('login'))
    
    network_code = request.form.get('network_code')
    if network_code and network_code.isdigit():
        session['network_code'] = network_code
    
    return redirect(url_for('home'))


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/authorize')
def authorize():
    # Use the google_auth_oauthlib library for the web flow
    flow = Flow.from_client_config(
        client_config={"web": {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}},
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    # Also use the google_auth_oauthlib library here
    state = session['state']
    flow = Flow.from_client_config(
        client_config={"web": {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}},
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI
    )
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    # Store credentials and user info
    session['credentials'] = credentials_to_dict(flow.credentials)
    
    from googleapiclient.discovery import build
    user_info_service = build('oauth2', 'v2', credentials=flow.credentials)
    user_info = user_info_service.userinfo().get().execute()
    session['user_info'] = user_info
    
    return redirect(url_for('home'))
@app.route('/debug')
def debug():
    # This page will show us the exact configuration the live server is using.
    # This helps us see if our environment variables are being loaded correctly.
    output = f"""
    <h1>Application Configuration Debug</h1>
    <p>This page shows the settings your app is currently running with on the server.</p>
    <hr>
    <h2>Values from Environment Variables:</h2>
    <p><b>GOOGLE_CLIENT_ID:</b> {os.getenv('GOOGLE_CLIENT_ID')}</p>
    <p><b>GOOGLE_REDIRECT_URI:</b> {os.getenv('GOOGLE_REDIRECT_URI')}</p>
    <hr>
    <h2>Value Being Used in the Code:</h2>
    <p><b>REDIRECT_URI variable is set to:</b> {REDIRECT_URI}</p>
    """
    return output

# --- Run the App ---
if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='localhost', port=5000, debug=True)