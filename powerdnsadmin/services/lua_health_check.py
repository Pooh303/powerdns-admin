import re
import asyncio
import socket
import aiohttp
from typing import Dict, List, Set, Tuple
from datetime import datetime
from ..models.record import Record
from ..models.base import db
from ..models.domain import Domain
from flask import current_app
from ..models.setting import Setting

class LuaHealthCheckService:
    def __init__(self):
        self._running = False
        self._check_interval = 30 
        self.session = None

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def check_domain_lua_records(self, domain_name):
        """Check health status of LUA records in a domain"""
        try:
            await self.init_session()
            
            # Get settings within application context
            with current_app.app_context():
                pdns_api_key = Setting().get('pdns_api_key')
                pdns_api_url = Setting().get('pdns_api_url')
            
            # Get LUA records directly from PowerDNS API
            headers = {
                'X-API-Key': pdns_api_key,
                'Content-Type': 'application/json'
            }
            
            # Get zone info
            url = f"{pdns_api_url}/api/v1/servers/localhost/zones/{domain_name}"
            async with self.session.get(url, headers=headers) as response:
                if response.status != 200:
                    return {
                        'status': 'error',
                        'message': f'Failed to get zone info: {response.status}'
                    }
                
                zone_data = await response.json()
                lua_records = []
                
                # Filter only LUA records
                for record in zone_data.get('records', []):
                    if record.get('type') == 'LUA':
                        lua_records.append({
                            'name': record.get('name'),
                            'content': record.get('content'),
                            'ttl': record.get('ttl')
                        })
                
                if not lua_records:
                    return None
                
                results = {}
                for record in lua_records:
                    try:
                        # For LUA records, we'll just check if they're valid
                        # by parsing the content
                        content = record['content']
                        if 'ifportup' in content:
                            # Basic validation of LUA record format
                            results[record['name']] = {
                                'status': 'valid',
                                'last_check': datetime.utcnow().isoformat(),
                                'details': {
                                    'content': record['content'],
                                    'ttl': record['ttl'],
                                    'type': 'LUA'
                                }
                            }
                        else:
                            results[record['name']] = {
                                'status': 'invalid',
                                'last_check': datetime.utcnow().isoformat(),
                                'error': 'Invalid LUA record format'
                            }
                    except Exception as e:
                        results[record['name']] = {
                            'status': 'invalid',
                            'last_check': datetime.utcnow().isoformat(),
                            'error': str(e)
                        }
                
                return results
        finally:
            await self.close_session()

# Create a singleton instance
lua_health_check_service = LuaHealthCheckService() 