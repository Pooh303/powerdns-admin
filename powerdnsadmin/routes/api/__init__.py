from flask import Blueprint

# Main API blueprint with /api/v1 prefix
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Import all API routes
from .health import *
from .lua_health import * 