from flask import jsonify, current_app
from ...services.lua_health_check import lua_health_check_service
from ...models.domain import Domain
import asyncio
import json
from ...decorators import apikey_auth
from . import api_bp

@api_bp.route('/servers/localhost/zones/<domain>/lua-health', methods=['GET'])
@apikey_auth
def check_domain_lua(domain):
    """Check LUA records health for a specific domain"""
    try:
        with current_app.app_context():
            results = asyncio.run(lua_health_check_service.check_domain_lua_records(domain))
            response_data = {
                'status': 'success',
                'domain': domain,
                'data': results
            }
            return jsonify(response_data)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/servers/localhost/zones/lua-health', methods=['GET'])
@apikey_auth
def check_all_domains():
    """Check LUA records health for all domains"""
    try:
        with current_app.app_context():
            domains = Domain.query.all()
            all_results = {}
            
            for domain in domains:
                results = asyncio.run(lua_health_check_service.check_domain_lua_records(domain.name))
                if results:  # Only include domains that have LUA records
                    all_results[domain.name] = results
            
            return jsonify({
                'status': 'success',
                'data': all_results
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500 