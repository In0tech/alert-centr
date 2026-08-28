from flask import Blueprint, request, redirect, session, url_for, render_template, abort
import uuid
import urllib.parse
import requests
from flask_login import login_user, logout_user, current_user, LoginManager, login_required

from datetime import datetime
from datetime import timedelta 
from jwt import decode_complete


bp = Blueprint("auth_pages", __name__)


from  alert_center.models import login_manager, User, db  


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


import configparser
import os

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', '..', 'alert_center.conf'))

################################################
################################################

"""
@bp.route("/login")
def login():   
    #new_user = User(username='admin', is_active = True)
    #new_user.set_unusable_password()
    #db.session.add(new_user)
    #db.session.commit()#'''
     
    import time 
    time.sleep(3)
    
    user = User.query.filter_by(username='admin').first()
    if user:
        login_user(user)
        return redirect(url_for("pages.home"))
    else:
        return "no user created"
    #return render_template("pages/home.html")

@bp.route("/logout")
def logout():
    logout_user()
    return "out"#redirect(url_for("auth_pages.login"))  #"""

################################################
################################################

#'''

#from alert_center.oidc_credentials import oidc_issuer_url, oidc_client_id, oidc_client_secret, oidc_client_name


oidc_issuer_url = config.get('OIDC', 'ISSUER_URL')
oidc_client_id = config.get('OIDC', 'CLIENT_ID')
oidc_client_secret = config.get('OIDC', 'CLIENT_SECRET')
oidc_client_name = config.get('OIDC', 'CLIENT_NAME')


auth_redirect_uri = "https://ddos-info.antiddos.cloud.vimpelcom.ru:8000/auth_callback"
post_logout_redirect_uris = "https://ddos-info.antiddos.cloud.vimpelcom.ru:8000"

verify_ssl = False


@bp.route("/logout")
def logout():
    logout_user()
    try:
        payload = {
            "post_logout_redirect_uri": post_logout_redirect_uris,
            "state": session["auth_state"],
            "id_token_hint":  session["id_token"]
        }
        url = f"{oidc_issuer_url}/oauth2/sessions/logout"
        
        resp = requests.post(url, data=payload, headers={"Accept": "application/json"},
                            timeout=10.0, verify=True)    
    except:
        pass 
    
    if request.method == "POST":
        print("Logout")
        
    return render_template("pages/logout.html")



def validate_token(id_token, access_token, client_id):
    return decode_complete(id_token, options={"verify_signature": False}).get("payload")

def oauth2_token_to_session(oauth2_token, session):
    if id_token := oauth2_token.get("id_token"):
        access_token = oauth2_token.get("access_token")
        refresh_token = oauth2_token.get("refresh_token")
        expires_in = oauth2_token.get("expires_in", 0)
        expires_at = datetime.now() + timedelta(seconds=int(float(expires_in) * 0.95) if expires_in else timedelta(seconds=0))
        session["userinfo"] = validate_token(id_token, access_token, oidc_client_id)
        session["id_token"] = id_token
        session["refresh_token"] = refresh_token
        session["expires_at"] = expires_at.isoformat()
        return session
    return None

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(session.get("path", "/"))
        #return render_template("pages/login.html")

    if not all([oidc_issuer_url, oidc_client_id, auth_redirect_uri]):
        abort(400, "OIDC not configured")

    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    session["auth_state"] = state
    session["path"] = request.form.get("next", "/")

    auth_url = (
        f"{oidc_issuer_url}/oauth2/auth?"
        + urllib.parse.urlencode(
            {
                "client_id": oidc_client_id,
                "scope": "openid offline",
                "response_type": "code",
                "state": state,
                "nonce": nonce,
                "prompt": "login",
                "redirect_uri": auth_redirect_uri,
                "status_code": 307,
            }
        )
    )
    return redirect(auth_url)

@bp.route("/auth_callback")
def auth_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        abort(400, "Missing code or state")
    if state != session.get("auth_state"):
        abort(400, "Invalid state")

    session.pop("auth_state", None)

    if not oidc_issuer_url:
        abort(400, "OIDC issuer not configured")

    payload = {
        "client_id": oidc_client_id,
        "client_secret": oidc_client_secret,
        "redirect_uri": auth_redirect_uri,
        "code": code,
        "grant_type": "authorization_code",
        "response_type": "token",
    }
    url = f"{oidc_issuer_url}/oauth2/token"
    try:
        resp = requests.post(
            url, data=payload, headers={"Accept": "application/json"},
            timeout=10, verify=verify_ssl
        )
        oauth2_token = resp.json()
    except Exception as e:
        abort(400, f"Token exchange failed - callback error: {e}")

    if resp.status_code == 200:
        oauth2_token_to_session(oauth2_token, session)
    else:
        abort(400, "Token exchange failed - token error")

    userinfo = session.get("userinfo", {})
    groups = userinfo.get("group", [])
    
    print(userinfo['email'])

    if "APP_ANTIDDOS_Users_MS" not in groups:# and 'APP_NSPA_Users_MS' not in groups:
        #if 'LVelueta@beeline.ru' != userinfo['email']:
        if not ('NDVinogradov@beeline.ru' == userinfo['email'] \
            or 'VTurpanov@beeline.ru' == userinfo['email']):
            abort(400, f"Не в группе ¯\\_(ツ)_/¯  APP_ANTIDDOS_Users_MS - {groups}")

    username = userinfo.get("login")
    email = userinfo.get("email", "")

    if not username:
        abort(400, "No username returned by identity provider")

    user = User.query.filter_by(username=username).first()
    created = False
    if not user:
        user = User(username=username, email=email, is_active=True)
        
        user.set_unusable_password()
        db.session.add(user)
        db.session.commit()
        created = True
    else:
        if not user.has_usable_password():
            user.set_unusable_password()
            db.session.commit()

    login_user(user)

    return redirect(session.get("path", "/"))#'''

