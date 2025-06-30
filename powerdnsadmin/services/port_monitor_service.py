import threading
import time
from datetime import datetime
from flask import current_app
from ..models.domain import Domain
from ..models.setting import Setting
from ..routes.load_balance import parse_lua_ifportup
from .email_service import send_port_status_change_alert
import socket

import logging
logger = logging.getLogger(__name__)

def check_single_port_status(ip, port, timeout=2):
    print(f"CSP: Attempting to check {ip}:{port} (timeout: {timeout}s) at {time.strftime('%H:%M:%S')}")
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print(f"CSP: Socket created for {ip}:{port}")
        sock.settimeout(timeout)
        # print(f"CSP: Timeout set for {ip}:{port}")
        result = sock.connect_ex((ip, int(port)))
        # print(f"CSP: connect_ex for {ip}:{port} returned: {result}")
    except socket.timeout:
        print(f"CSP: TIMEOUT for {ip}:{port} after {time.time() - start_time:.2f}s")
        return False
    except OSError as e:
        print(f"CSP: OSERROR for {ip}:{port}: {e} after {time.time() - start_time:.2f}s")
        return False
    except Exception as e:
        print(f"CSP: EXCEPTION for {ip}:{port}: {e} after {time.time() - start_time:.2f}s")
        # It's better to close socket in finally if an error occurs before close
        try:
            sock.close()
        except NameError: # sock might not be defined if socket.socket fails
            pass
        except Exception: # other errors during close
            pass
        return False
    
    # Close socket if no exception during connect_ex
    try:
        sock.close()
    except Exception as e:
        print(f"CSP: EXCEPTION during close for {ip}:{port}: {e}")
        # Decide if this should mean the port is down
    
    elapsed_time = time.time() - start_time
    status_str = 'UP' if result == 0 else 'DOWN'
    print(f"CSP: Result for {ip}:{port} is {status_str} (code: {result}), took {elapsed_time:.2f}s")
    return result == 0

# def check_single_port_status(ip, port, timeout=2):
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(timeout)
#         result = sock.connect_ex((ip, int(port)))
#         sock.close()
#         return result == 0
#     except Exception:
#         return False

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

    # def _get_lua_backends_to_monitor(self):
    #     """
    #     Fetches all LUA records and their backend IPs/ports.
    #     This logic is similar to the dashboard in load_balance.py
    #     """
    #     backends = [] # List of dicts: [{'lua_name': str, 'ip': str, 'port': int}]
    #     if not self.app: return backends

    #     with self.app.app_context():
    #         try:
    #             domain_api = Domain()
    #             zones_result = domain_api.get_domains()
    #             if not zones_result:
    #                 current_app.logger.info("LBM: No zones found.")
    #                 return backends

    #             for zone_data in zones_result:
    #                 zone_actual_name = zone_data.get('name')
    #                 if not zone_actual_name:
    #                     continue
    #                 zone_info = domain_api.get_domain_info(zone_actual_name)
    #                 if not zone_info or 'rrsets' not in zone_info:
    #                     continue
    #                 for rrset in zone_info.get('rrsets', []):
    #                     if rrset.get('type') == 'LUA' and rrset.get('records') and rrset['records']:
    #                         record = rrset['records'][0]
    #                         content = record.get('content', '')
    #                         port_str, ips_list = parse_lua_ifportup(content)
    #                         if port_str is not None and ips_list:
    #                             port = int(port_str)
    #                             lua_record_name = rrset.get('name','').rstrip('.')
    #                             for ip in ips_list:
    #                                 backends.append({
    #                                     'lua_name': lua_record_name,
    #                                     'ip': ip,
    #                                     'port': port
    #                                 })
    #         except Exception as e:
    #             current_app.logger.error(f"LBM: Error fetching LUA backends: {e}")
    #     return backends


    def _get_lua_backends_to_monitor(self):
        backends = []
        if not self.app:
            # Consider using a direct print or a pre-app-context logger if self.app isn't available
            print("LBM (_get_lua_backends): Flask app not initialized.")
            return backends

        with self.app.app_context(): # Ensure app_context for logger and DB access
            current_app.logger.debug("LBM (_get_lua_backends): Starting to fetch LUA backends.")
            try:
                domain_api = Domain()
                zones_result = domain_api.get_domains() # This calls PDNS API
                if not zones_result:
                    current_app.logger.info("LBM (_get_lua_backends): No zones found from API.")
                    return backends
                current_app.logger.debug(f"LBM (_get_lua_backends): Found {len(zones_result)} zones.")

                for zone_data in zones_result:
                    zone_actual_name = zone_data.get('name')
                    if not zone_actual_name:
                        current_app.logger.warning("LBM (_get_lua_backends): Zone data found without a name.")
                        continue
                    current_app.logger.debug(f"LBM (_get_lua_backends): Processing zone: {zone_actual_name}")
                    zone_info = domain_api.get_domain_info(zone_actual_name) # This calls PDNS API
                    if not zone_info or 'rrsets' not in zone_info:
                        current_app.logger.info(f"LBM (_get_lua_backends): No rrsets found for zone: {zone_actual_name}")
                        continue
                    
                    current_app.logger.debug(f"LBM (_get_lua_backends): Found {len(zone_info.get('rrsets', []))} rrsets in zone {zone_actual_name}.")
                    for rrset in zone_info.get('rrsets', []):
                        if rrset.get('type') == 'LUA' and rrset.get('records') and rrset['records']:
                            record = rrset['records'][0]
                            content = record.get('content', '')
                            current_app.logger.debug(f"LBM (_get_lua_backends): Found LUA record '{rrset.get('name')}' with content: '{content[:50]}...'") # Log part of content
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
                                    current_app.logger.debug(f"LBM (_get_lua_backends): Added backend to monitor: {lua_record_name}, {ip}:{port}")
                            # else:
                            #    current_app.logger.debug(f"LBM (_get_lua_backends): LUA record '{rrset.get('name')}' did not parse to a monitorable backend (port: {port_str}, ips: {ips_list})")
            except Exception as e:
                current_app.logger.error(f"LBM (_get_lua_backends): Error fetching LUA backends: {e}", exc_info=True)
            
            current_app.logger.debug(f"LBM (_get_lua_backends): Finished fetching. Total backends to monitor: {len(backends)}")
        return backends


    # def _monitor_loop(self):
    #     if not self.app:
    #         print("LuaBackendMonitorService: Flask app not initialized. Stopping monitor loop.")
    #         self.running = False
    #         return

    #     with self.app.app_context():
    #         current_app.logger.info("LBM: LuaBackendMonitorService loop started.")
    #         while self.running:
    #             try:
    #                 backends_to_check = self._get_lua_backends_to_monitor()
    #                 if not backends_to_check:
    #                     current_app.logger.info("LBM: No LUA backends to monitor currently.")
    #                 else:
    #                     current_app.logger.debug(f"LBM: Checking {len(backends_to_check)} LUA backends.")

    #                 new_statuses = {}
    #                 for backend in backends_to_check:
    #                     lua_name = backend['lua_name']
    #                     ip = backend['ip']
    #                     port = backend['port']
    #                     status_key = (lua_name, ip, port)

    #                     is_currently_up = check_single_port_status(ip, port)
    #                     current_status_str = 'UP' if is_currently_up else 'DOWN'
    #                     new_statuses[status_key] = current_status_str

    #                     previous_status_str = self.backend_statuses.get(status_key)

    #                     if previous_status_str is not None and previous_status_str != current_status_str:
    #                         current_app.logger.info(
    #                             f"LBM: Status change for {lua_name} backend {ip}:{port} - From {previous_status_str} to {current_status_str}"
    #                         )
    #                         send_port_status_change_alert(lua_name, ip, port, current_status_str)
    #                     elif previous_status_str is None:
    #                          current_app.logger.info(f"LBM: Initial status for {lua_name} backend {ip}:{port} is {current_status_str}")


    #                 self.backend_statuses = new_statuses

    #             except Exception as e:
    #                 current_app.logger.error(f"LBM: Error in monitor loop: {e}", exc_info=True)

    #             # Wait for the next check interval, accounting for the time taken by checks
    #             # This is a simple way; more robust schedulers exist (APScheduler)
    #             time.sleep(self.check_interval)
    #         current_app.logger.info("LBM: LuaBackendMonitorService loop stopped.")


    def _monitor_loop(self):
        if not self.app:
            print("LBM: Flask app not initialized. Stopping monitor loop.") # Use print if logger might not be available
            self.running = False
            return

        with self.app.app_context(): # Ensure app_context for logger and other Flask features
            current_app.logger.info("LBM: >>> LuaBackendMonitorService _monitor_loop started <<<") # Log loop start
            while self.running:
                try:
                    current_app.logger.debug("LBM: --- Top of _monitor_loop iteration ---") # Log each iteration
                    backends_to_check = self._get_lua_backends_to_monitor()
                    if not backends_to_check:
                        current_app.logger.info("LBM: No LUA backends to monitor currently.")
                    else:
                        current_app.logger.info(f"LBM: Found {len(backends_to_check)} LUA backends to check: {backends_to_check}") # Log what it found

                    new_statuses = {}
                    for backend in backends_to_check:
                        lua_name = backend['lua_name']
                        ip = backend['ip']
                        port = backend['port']
                        status_key = (lua_name, ip, port)
                        current_app.logger.debug(f"LBM: Checking backend: {lua_name} - {ip}:{port}")

                        is_currently_up = check_single_port_status(ip, port)
                        current_status_str = 'UP' if is_currently_up else 'DOWN'
                        new_statuses[status_key] = current_status_str
                        current_app.logger.debug(f"LBM: Backend {ip}:{port} current status: {current_status_str}")

                        previous_status_str = self.backend_statuses.get(status_key)
                        current_app.logger.debug(f"LBM: Backend {ip}:{port} previous status: {previous_status_str}")
                        
                        print(f"LBM_PRINT: Backend {ip}:{port} - Current: '{current_status_str}', Previous: '{previous_status_str}'")


                        if previous_status_str is not None and previous_status_str != current_status_str:
                            current_app.logger.info(
                                f"LBM: Status change DETECTED for {lua_name} backend {ip}:{port} - From {previous_status_str} to {current_status_str}. Attempting to send alert."
                            )
                            print(f"LBM_PRINT: STATUS CHANGE DETECTED for {lua_name} ({ip}:{port}) from '{previous_status_str}' to '{current_status_str}'. Calling send_port_status_change_alert.")
                            send_port_status_change_alert(lua_name, ip, port, current_status_str)
                        elif previous_status_str is None:
                            current_app.logger.info(f"LBM: Initial status for {lua_name} backend {ip}:{port} is {current_status_str}")
                        else:
                            # current_app.logger.debug(f"LBM: No status change for {lua_name} backend {ip}:{port}. Current: {current_status_str}, Previous: {previous_status_str}")
                            print(f"LBM_PRINT: No status change for {lua_name} ({ip}:{port}). Stays '{current_status_str}'.")

                    self.backend_statuses = new_statuses
                    current_app.logger.debug(f"LBM: Updated backend_statuses: {self.backend_statuses}")
                    print(f"LBM_PRINT: All backend_statuses after this iteration: {self.backend_statuses}")

                except Exception as e:
                    current_app.logger.error(f"LBM: Error in monitor loop: {e}", exc_info=True)

                current_app.logger.debug(f"LBM: --- End of _monitor_loop iteration, sleeping for {self.check_interval}s ---")
                time.sleep(self.check_interval)
            current_app.logger.info("LBM: >>> LuaBackendMonitorService _monitor_loop stopped <<<")


    # def start(self):
    #     if not self.running and self.app:
    #         self.running = True
            
    #         # Initialize statuses for the first run
    #         initial_backends = self._get_lua_backends_to_monitor()
    #         with self.app.app_context():
    #             for backend in initial_backends:
    #                 status_key = (backend['lua_name'], backend['ip'], backend['port'])
    #                 is_up = check_single_port_status(backend['ip'], backend['port'])
    #                 self.backend_statuses[status_key] = 'UP' if is_up else 'DOWN'
    #                 current_app.logger.info(f"LBM: Initializing status for {backend['lua_name']} backend {backend['ip']}:{backend['port']} as {self.backend_statuses[status_key]}")


    #         self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
    #         self.thread.start()

    #         with self.app.app_context():
    #             current_app.logger.info(f"LBM: LuaBackendMonitorService started. Check interval: {self.check_interval}s")
    #     elif not self.app:
    #         print("LuaBackendMonitorService: Cannot start, Flask app not initialized.")
    #     elif self.running:
    #         with self.app.app_context():
    #             current_app.logger.info("LBM: LuaBackendMonitorService is already running.")

    def start(self):
        if not self.app:
            # Use print for critical startup issues before logger might be fully available
            print("LBM: LuaBackendMonitorService: Cannot start, Flask app not initialized.")
            self.running = False # Ensure running is false
            return

        # Check the setting *before* deciding to run the thread
        with self.app.app_context(): # Need app_context to use Setting() and current_app.logger
            try:
                # Explicitly get the setting
                monitor_enabled = Setting().get('enable_lua_backend_monitor')
                if not monitor_enabled:
                    current_app.logger.info("LBM: LuaBackendMonitorService is disabled by 'enable_lua_backend_monitor' setting. Not starting monitor thread.")
                    self.running = False # Mark as not running
                    return # Exit start method, do not start the thread
            except Exception as e:
                current_app.logger.error(f"LBM: Error reading 'enable_lua_backend_monitor' setting: {e}. Assuming disabled.")
                self.running = False
                return


        # Proceed only if monitor_enabled was true and no errors occurred
        if not self.running: # Check self.running again, it might have been set to False by the logic above
            self.running = True
            # Initialize statuses for the first run
            initial_backends = self._get_lua_backends_to_monitor() # This needs app_context if not already in one
            with self.app.app_context(): # Ensure app_context for logging and potentially DB access in _get_lua_backends
                for backend in initial_backends:
                    status_key = (backend['lua_name'], backend['ip'], backend['port'])
                    is_up = check_single_port_status(backend['ip'], backend['port'])
                    self.backend_statuses[status_key] = 'UP' if is_up else 'DOWN'
                    current_app.logger.info(f"LBM: Initializing status for {backend['lua_name']} backend {backend['ip']}:{backend['port']} as {self.backend_statuses[status_key]}")

            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            with self.app.app_context(): # app_context for logger
                current_app.logger.info(f"LBM: LuaBackendMonitorService started. Check interval: {self.check_interval}s")
        # elif not self.app: # This case is now handled at the beginning
        #     print("LuaBackendMonitorService: Cannot start, Flask app not initialized.")
        elif self.running: # This means it was already running, or the enable check passed and it's now set to run
            with self.app.app_context(): # app_context for logger
                current_app.logger.info("LBM: LuaBackendMonitorService is already running or has just been started.")


    def stop(self):
        if self.running:
            self.running = False
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=self.check_interval + 5)
            with self.app.app_context():
                current_app.logger.info("LBM: LuaBackendMonitorService stopped.")