import threading
import time
from datetime import datetime
from flask import current_app
from ..models.domain import Domain # ต้อง import model ที่เกี่ยวข้อง
from ..models.setting import Setting # ถ้าจะใช้ Setting ภายใน service
from ..routes.load_balance import parse_lua_ifportup
from .email_service import send_port_status_change_alert # import email function

import socket
def check_single_port_status(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        return result == 0
    except Exception:
        return False

class LuaBackendMonitorService:
    def __init__(self, app=None):
        self.app = app
        self.check_interval = 60
        self.backend_statuses = {}
        self.running = False
        self.thread = None

    def init_app(self, app):
        self.app = app
        with app.app_context():
            retrieved_interval = Setting().get('lua_backend_monitor_interval')
            if retrieved_interval is not None:
                try:
                    self.check_interval = int(retrieved_interval)
                    current_app.logger.info(f"LBM: Interval set from Setting 'lua_backend_monitor_interval': {self.check_interval}s")
                except ValueError:
                    default_from_config = current_app.config.get('LUA_BACKEND_MONITOR_INTERVAL', 60)
                    self.check_interval = int(default_from_config)
                    current_app.logger.warning(f"LBM: Invalid value for 'lua_backend_monitor_interval' ('{retrieved_interval}'). Using config/default: {self.check_interval}s")
            else:
                default_from_config = current_app.config.get('LUA_BACKEND_MONITOR_INTERVAL', 60)
                self.check_interval = int(default_from_config)
                current_app.logger.warning(f"LBM: Setting 'lua_backend_monitor_interval' not found. Using config/default: {self.check_interval}s")

    def _get_lua_backends_to_monitor(self):
        """
        Fetches all LUA records and their backend IPs/ports.
        This logic is similar to the dashboard in load_balance.py
        """
        backends = [] # List of dicts: [{'lua_name': str, 'ip': str, 'port': int}]
        if not self.app: return backends

        with self.app.app_context():
            try:
                domain_api = Domain()
                zones_result = domain_api.get_domains()
                if not zones_result:
                    current_app.logger.info("LBM: No zones found.")
                    return backends

                for zone_data in zones_result:
                    zone_actual_name = zone_data.get('name')
                    if not zone_actual_name:
                        continue
                    zone_info = domain_api.get_domain_info(zone_actual_name)
                    if not zone_info or 'rrsets' not in zone_info:
                        continue
                    for rrset in zone_info.get('rrsets', []):
                        if rrset.get('type') == 'LUA' and rrset.get('records') and rrset['records']:
                            record = rrset['records'][0]
                            content = record.get('content', '')
                            port_str, ips_list = parse_lua_ifportup(content)
                            if port_str is not None and ips_list:
                                port = int(port_str)
                                lua_record_name = rrset.get('name','').rstrip('.')
                                for ip in ips_list:
                                    backends.append({
                                        'lua_name': lua_record_name,
                                        'ip': ip,
                                        'port': port
                                    })
            except Exception as e:
                current_app.logger.error(f"LBM: Error fetching LUA backends: {e}")
        return backends

    def _monitor_loop(self):
        if not self.app:
            print("LuaBackendMonitorService: Flask app not initialized. Stopping monitor loop.")
            self.running = False
            return

        with self.app.app_context():
            current_app.logger.info("LBM: LuaBackendMonitorService loop started.")
            while self.running:
                try:
                    backends_to_check = self._get_lua_backends_to_monitor()
                    if not backends_to_check:
                        current_app.logger.info("LBM: No LUA backends to monitor currently.")
                    else:
                        current_app.logger.debug(f"LBM: Checking {len(backends_to_check)} LUA backends.")

                    new_statuses = {}
                    for backend in backends_to_check:
                        lua_name = backend['lua_name']
                        ip = backend['ip']
                        port = backend['port']
                        status_key = (lua_name, ip, port)

                        is_currently_up = check_single_port_status(ip, port)
                        current_status_str = 'UP' if is_currently_up else 'DOWN'
                        new_statuses[status_key] = current_status_str

                        previous_status_str = self.backend_statuses.get(status_key)

                        if previous_status_str is not None and previous_status_str != current_status_str:
                            current_app.logger.info(
                                f"LBM: Status change for {lua_name} backend {ip}:{port} - From {previous_status_str} to {current_status_str}"
                            )
                            send_port_status_change_alert(lua_name, ip, port, current_status_str)
                        elif previous_status_str is None:
                             current_app.logger.info(f"LBM: Initial status for {lua_name} backend {ip}:{port} is {current_status_str}")


                    self.backend_statuses = new_statuses

                except Exception as e:
                    current_app.logger.error(f"LBM: Error in monitor loop: {e}", exc_info=True)

                # Wait for the next check interval, accounting for the time taken by checks
                # This is a simple way; more robust schedulers exist (APScheduler)
                time.sleep(self.check_interval)
            current_app.logger.info("LBM: LuaBackendMonitorService loop stopped.")


    def start(self):
        if not self.running and self.app:
            self.running = True
            # Initialize statuses for the first run
            initial_backends = self._get_lua_backends_to_monitor()
            with self.app.app_context():
                for backend in initial_backends:
                    status_key = (backend['lua_name'], backend['ip'], backend['port'])
                    is_up = check_single_port_status(backend['ip'], backend['port'])
                    self.backend_statuses[status_key] = 'UP' if is_up else 'DOWN'
                    current_app.logger.info(f"LBM: Initializing status for {backend['lua_name']} backend {backend['ip']}:{backend['port']} as {self.backend_statuses[status_key]}")


            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            with self.app.app_context():
                current_app.logger.info(f"LBM: LuaBackendMonitorService started. Check interval: {self.check_interval}s")
        elif not self.app:
            print("LuaBackendMonitorService: Cannot start, Flask app not initialized.")
        elif self.running:
            with self.app.app_context():
                current_app.logger.info("LBM: LuaBackendMonitorService is already running.")


    def stop(self):
        if self.running:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=self.check_interval + 5)
            with self.app.app_context():
                current_app.logger.info("LBM: LuaBackendMonitorService stopped.")