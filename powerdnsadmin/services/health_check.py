import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Optional
from ..models.server import Server
from ..models.server_health import ServerHealth
from ..models.base import db

class HealthCheckService:
    def __init__(self):
        self.session = None
        self._running = False
        self._check_interval = 30  # seconds between checks

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def check_server_health(self, server: Server) -> Dict:
        """Check health status of a server"""
        try:
            await self.init_session()
            
            # Check if server is reachable
            try:
                async with self.session.get(f"{server.api_url}/api/v1/servers") as response:
                    if response.status == 200:
                        return {
                            'status': 'healthy',
                            'last_check': datetime.utcnow().isoformat(),
                            'details': await response.json()
                        }
            except Exception as e:
                return {
                    'status': 'unhealthy',
                    'last_check': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
        finally:
            await self.close_session()

    def update_server_status(self, server: Server, status: Dict) -> None:
        """Update server health status in database"""
        try:
            health_record = ServerHealth.query.filter_by(server_id=server.id).first()
            if not health_record:
                health_record = ServerHealth(server_id=server.id)
            
            health_record.status = status['status']
            health_record.last_check = datetime.utcnow()
            health_record.details = status
            
            db.session.add(health_record)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

    async def check_port(self, host: str, port: int, timeout: float = 3.0) -> bool:
        try:
            # Create a new socket for each check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: sock.connect_ex((host, port))
            )
            sock.close()
            return result == 0
        except Exception:
            return False

    async def check_server(self, server: Server) -> Dict:
        """Check health of a single server"""
        is_alive = await self.check_port(server.ip, server.port)
        
        # Update server status in database
        server.last_check = datetime.utcnow()
        server.is_alive = is_alive
        db.session.commit()
        
        return {
            "server_id": server.id,
            "name": server.name,
            "ip": server.ip,
            "port": server.port,
            "is_alive": is_alive,
            "last_check": server.last_check
        }

    async def check_all_servers(self) -> List[Dict]:
        """Check health of all servers"""
        servers = Server.query.all()
        tasks = [self.check_server(server) for server in servers]
        return await asyncio.gather(*tasks)

    async def start_monitoring(self):
        """Start the monitoring loop"""
        self._running = True
        while self._running:
            try:
                await self.check_all_servers()
                await asyncio.sleep(self._check_interval)
            except Exception as e:
                print(f"Error in health check loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying

    def stop_monitoring(self):
        """Stop the monitoring loop"""
        self._running = False

# Create a singleton instance
health_check_service = HealthCheckService() 