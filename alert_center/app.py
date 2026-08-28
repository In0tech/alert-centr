from flask import Flask
from flask_login import LoginManager

from alert_center.views import auth_pages
from alert_center.views import pages
from alert_center.views import genie_interactive
from alert_center.views import alert_interactive
from alert_center.views.genie_interactive import create_genie_dash
from alert_center.views.alert_interactive import create_alert_detail_app, create_alerts_table_app
from alert_center.views.reports_interactive import create_reports_app
from alert_center.views.metrics_interactive import create_metrics_app
from alert_center.views.search_interactive import create_search_app
from alert_center.views.db_assist_interactive import create_db_assist_app


from alert_center.models import login_manager, db


dash_apps_base_url = '/dashapp/'

def create_app():
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "supersecretkey"

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth_pages.login"

    app.register_blueprint(auth_pages.bp)
    app.register_blueprint(pages.bp)
    #app.register_blueprint(genie_interactive.bp)
    #app.register_blueprint(alert_interactive.bp)
    
    create_genie_dash(app, url_base_pathname=dash_apps_base_url+'genie_dash/')#genie_dash_apps_url) 
    create_alerts_table_app(app, url_base_pathname=dash_apps_base_url+'alert_table_dashapp/')# '/alert_table_dashapp/')
    create_alert_detail_app(app, url_base_pathname=dash_apps_base_url+'alert_dashapp/')# '/alert_dashapp/')

    create_reports_app(app, url_base_pathname=dash_apps_base_url+'reports_dashapp/')
    create_metrics_app(app, url_base_pathname=dash_apps_base_url+'metrics_dashapp/')
    create_search_app(app, url_base_pathname=dash_apps_base_url+'search_dashapp/')
    create_db_assist_app(app, url_base_pathname=dash_apps_base_url+'db_assist_dashapp/')


    return app

app = create_app()
with app.app_context():
    db.create_all()


from flask import request, redirect, url_for
from flask_login import current_user
@app.before_request
def protect_dash():
    if 'dashapp' in request.path and not current_user.is_authenticated:
        return redirect(url_for('auth_pages.login'))
'''
        (request.path.startswith(genie_dash_apps_url) \
      or request.path.startswith('/alert_table_dashapp/') or request.path.startswith('/alert_dashapp/')) \
'''

# python -m flask --app alert_center.app run --host 0.0.0.0 --port 8000 --debug

# gunicorn alert_center:app --bind 0.0.0.0:443 --certfile ../ssl/nspa.crt --keyfile ../ssl/nspa.key --workers 3

