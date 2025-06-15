#!/usr/bin/env python3
from powerdnsadmin import create_app
import logging
from flask_migrate import upgrade
logging.getLogger('werkzeug').setLevel(logging.WARNING)

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        upgrade()  # Run database migrations
    app.run(debug=True, host=app.config.get('BIND_ADDRESS', '127.0.0.1'), port=app.config.get('PORT', '9191'))
