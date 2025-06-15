from flask import jsonify
from ...services.health_check import health_check_service
from ...models.server import Server
from ...decorators import apikey_auth
import asyncio
from ..api import api_bp

@api_bp.route('/servers', methods=['GET'])
@apikey_auth
def get_servers_health():
    """Get health status for all servers"""
    try:
        servers = Server.query.all()
        results = {}
        
        for server in servers:
            results[server.name] = asyncio.run(health_check_service.check_server_health(server))
        
        return jsonify({
            'status': 'success',
            'data': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/servers/<server_id>', methods=['GET'])
@apikey_auth
def get_server_health(server_id):
    """Get health status for a specific server"""
    try:
        server = Server.query.filter_by(id=server_id).first()
        if not server:
            return jsonify({
                'status': 'error',
                'message': 'Server not found'
            }), 404
            
        result = asyncio.run(health_check_service.check_server_health(server))
        return jsonify({
            'status': 'success',
            'server': server.name,
            'data': result
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api_bp.route('/servers/check', methods=['POST'])
@apikey_auth
def check_servers_health():
    """Manually trigger health check for all servers"""
    try:
        servers = Server.query.all()
        results = {}
        
        for server in servers:
            results[server.name] = asyncio.run(health_check_service.check_server_health(server))
            # Update server status in database
            health_check_service.update_server_status(server, results[server.name])
        
        return jsonify({
            'status': 'success',
            'data': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500 