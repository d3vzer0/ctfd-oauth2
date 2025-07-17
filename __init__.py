import flask
from flask import render_template, request, redirect, session, url_for, current_app
from CTFd.models import db, Users
from CTFd.utils.decorators import admins_only
from CTFd.utils.security.auth import login_user
from wtforms import Form, StringField
from authlib.integrations.flask_client import OAuth
import os
import logging

logger = logging.getLogger("oauth2")


class Oauth2Config(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)  # type: ignore
    name = db.Column(db.Text)  # type: ignore
    client_id = db.Column(db.Text)  # type: ignore
    client_secret = db.Column(db.Text)  # type: ignore
    authority_url = db.Column(db.Text, nullable=False)  # type: ignore
    scope = db.Column(db.Text, default='openid email profile')  # type: ignore

    def __init__(self, name, client_id, client_secret, authority_url, scope):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.authority_url = authority_url


class Oauth2ClientForm(Form):
    name = StringField('name')
    client_id = StringField('client_id')
    client_secret = StringField('client_secret')
    authority_url = StringField('authority_url')
    scope = StringField('scope')


def load(app):
    # Silly override since some Oauth providers don't accept 127.0.0.1 over HTTP and only allow localhost
    if os.getenv('FLASK_ENV') == 'development':
        app.config['SERVER_NAME'] = 'localhost:4000'

    app.db.create_all()
    original_login = app.view_functions['auth.login']
    custom_auth = flask.Blueprint("oauth2", __name__, template_folder="templates", static_folder="assets")
    app.register_blueprint(custom_auth)

    oauth = OAuth(app)
    oauth._clients.clear()
    clients = Oauth2Config.query.all()
    for client in clients:
        well_known = f'{client.authority_url}/.well-known/openid-configuration'
        oauth.register(
            name=client.name.lower(),
            authority=client.authority_url,
            client_id=client.client_id,
            client_secret=client.client_secret,
            server_metadata_url=well_known,
            client_kwargs={'scope': client.scope}
        )

    @app.route('/loginfallback', methods=['GET', 'POST'])
    def login_fallback():
        return original_login()

    @app.before_request
    def override_login():
        if request.path == '/login':
            get_first_auth = Oauth2Config.query.first()
            redirect_uri = f"/oauth2/login/{get_first_auth.id}"
            return redirect(redirect_uri)

    # Section for oauth2 login flow
    @app.route('/oauth2', methods=['GET'])
    def oauth2_login():
        clients = Oauth2Config.query.all()
        # No need to pass client config details to the template, just the name and client id
        client_list = [{'name': client.name, 'id': client.id} for client in clients]
        return render_template('oauth2_login.html', clients=client_list)

    @app.route('/oauth2/login/<provider_id>', methods=['GET'])
    def oauth2_login_start(provider_id: str):
        provider = Oauth2Config.query.get_or_404(provider_id)
        client = oauth.create_client(provider.name.lower())
        if client is None:
            well_known = f'{provider.authority_url}/.well-known/openid-configuration'
            oauth.register(
                    name=provider.name.lower(),
                    authority=provider.authority_url,
                    client_id=provider.client_id,
                    client_secret=provider.client_secret,
                    server_metadata_url=well_known,
                    client_kwargs={'scope': provider.scope}
                )
            client = oauth.create_client(provider.name.lower())

        redirect_params = {'provider_id': provider_id, '_external': True}
        if os.getenv('FLASK_ENV') != 'development':
            redirect_params['_scheme'] = 'https'

        redirect_uri = url_for('oauth2_login_callback', **redirect_params)
        return client.authorize_redirect(redirect_uri)

    @app.route('/oauth2/login/<provider_id>/callback')
    def oauth2_login_callback(provider_id: str):
        provider = Oauth2Config.query.get_or_404(provider_id)
        client = oauth.create_client(provider.name.lower())
        if client is None:
            return redirect(url_for('oauth2_login'))

        token = client.authorize_access_token()
        user_info = client.userinfo(token=token)
        account = Users.query.filter_by(email=user_info["email"]).first()
        if not account:
            account = Users(
                name=user_info["email"],
                email=user_info["email"],
                type="user",
                verified=True
            )
            db.session.add(account)  # type: ignore
            db.session.commit()  # type: ignore

        session.regenerate()  # type: ignore
        with current_app.app_context():
            login_user(account)
            return redirect("/")

    # Section for oauth2 client/provider management
    @app.route('/admin/oauth2/clients', methods=['GET'])
    @admins_only
    def oauth2_clients():
        clients = Oauth2Config.query.all()
        return render_template('oauth2_client_list.html', clients=clients)

    @app.route('/admin/oauth2/clients/delete/<client_id>', methods=['POST'])
    @admins_only
    def oauth2_client_delete(client_id: str):
        client = Oauth2Config.query.get_or_404(client_id)
        db.session.delete(client)  # type: ignore
        db.session.commit()  # type: ignore
        return redirect(url_for('oauth2_clients'))

    @app.route('/admin/oauth2/clients/edit/<client_id>', methods=['GET', 'POST'])
    @admins_only
    def oauth2_client_edit(client_id: str):
        client = Oauth2Config.query.get_or_404(client_id)
        if request.method == 'GET':
            return render_template('oauth2_client_form.html', client=client)
        else:
            form = Oauth2ClientForm(request.form)
            db.session.query(Oauth2Config).filter_by(id=client_id).update({
                'name': form.name.data,
                'client_id': form.client_id.data,
                'client_secret': form.client_secret.data,
                'scope': form.scope.data,
                'authority_url': form.authority_url.data

            })
            db.session.commit()  # type: ignore
            return redirect(url_for('oauth2_clients'))

    @app.route('/admin/oauth2/clients/create', methods=['GET', 'POST'])
    @admins_only
    def oauth2_client_create():
        form = Oauth2ClientForm(request.form)
        if request.method == 'POST' and form.validate():
            client = Oauth2Config(
                name=form.name.data,
                client_id=form.client_id.data,
                client_secret=form.client_secret.data,
                authority_url=form.authority_url.data,
                scope=form.scope.data,
            )
            db.session.add(client)  # type: ignore
            db.session.commit()  # type: ignore
            return redirect(url_for('oauth2_clients'))

        else:
            return render_template('oauth2_client_form.html')
