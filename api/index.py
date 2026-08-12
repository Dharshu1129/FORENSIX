import os
import sys

# Ensure root directory is in sys.path for module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

app = create_app()

class VercelPathFixMiddleware(object):
    """
    WSGI Middleware to strip Vercel serverless function path prefixes (/api/index.py, /api/index)
    so Flask receives clean routes (/, /dashboard, /cases, /evidence, etc.)
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        path_info = environ.get('PATH_INFO', '')
        if path_info.startswith('/api/index.py'):
            environ['PATH_INFO'] = path_info[13:] or '/'
        elif path_info.startswith('/api/index'):
            environ['PATH_INFO'] = path_info[10:] or '/'
        elif path_info.startswith('/api'):
            environ['PATH_INFO'] = path_info[4:] or '/'
            
        return self.app(environ, start_response)

app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)
