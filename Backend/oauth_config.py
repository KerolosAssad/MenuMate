from authlib.integrations.flask_client import OAuth

oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id='870606905507-egrigp4l54mhapf1rb9mpcd5q3ki67hk.apps.googleusercontent.com',
        client_secret='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',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )


