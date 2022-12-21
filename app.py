import os
import pathlib

import requests
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests


app = Flask("Google Login App")
app.secret_key = "Hackbright"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # HTTPS work around => https://oauthlib.readthedocs.io/en/latest/oauth2/security.html

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
# https://stackoverflow.com/questions/61321503/is-there-a-pathlib-alternate-for-os-path-join

# https://google-auth-oauthlib.readthedocs.io/en/latest/reference/google_auth_oauthlib.flow.html
# https://google-auth-oauthlib.readthedocs.io/en/latest/_modules/google_auth_oauthlib/flow.html?highlight=authorization%20response#
flow = Flow.from_client_secrets_file(
    client_secrets_file = client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri = "http://127.0.0.1:5000/callback",
)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            abort(401) #authorziation required 
        else:
            return function() 

    return wrapper

@app.route('/login')
def login():
    
    authorization_url, state = flow.authorization_url(
        access_type = 'offline', 
        include_granted_scopes = 'true',
        )

    return redirect(authorization_url)

@app.route('/callback')
def callback():

    flow.fetch_token(authorization_response = request.url)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token = credentials._id_token,
        request = token_request,
        audience = GOOGLE_CLIENT_ID
    ) # id_info returns json response of user's log in data

    session["google_id"] = id_info.get("sub")
    session["family_name"] = id_info.get("family_name") #first name
    session["given_name"] = id_info.get("given_name") #last name

    return redirect("/protected_area")

@app.route('/logout')
def logout():
    # session.clear()
    session.pop("id_info", None)

    return redirect("/")

@app.route('/')
def index():

    return "<a href='/login'><button>Login</button></a>"

@app.route('/protected_area')
@login_is_required
def protected_area():

    return "<a href='/logout'><button>Logout</button></a>"

if __name__ == "__main__":
    app.run(debug=True)