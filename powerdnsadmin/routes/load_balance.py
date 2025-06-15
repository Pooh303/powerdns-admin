# powerdnsadmin/routes/load_balance.py

import datetime
import json
import re
import socket
import threading
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    current_app, g, session, abort, jsonify, flash
)
from flask_login import login_required, current_user, login_manager
from markupsafe import Markup
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urljoin

from ..models.user import User, Anonymous
from ..models.domain import Domain
from ..models.setting import Setting
from ..models.record import Record
from ..models.history import History
from ..decorators import operator_role_required
from ..models.base import db
from ..lib import utils

load_balance_bp = Blueprint('load_balance',
                            __name__,
                            template_folder='../templates',
                            url_prefix='/load-balance')

# Global connection pool
socket_pool = {}
socket_pool_lock = threading.Lock()

# Simple cache for status checks
status_cache = {}
status_cache_lock = threading.Lock()
CACHE_DURATION = 30  # seconds

def get_socket_from_pool(ip, port):
    """Get a socket from the pool or create a new one"""
    key = f"{ip}:{port}"
    with socket_pool_lock:
        if key in socket_pool:
            sock = socket_pool[key]
            if not sock._closed:
                return sock
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Reduced timeout to 1 second
        socket_pool[key] = sock
        return sock

def get_cached_status(ip, port):
    """Get cached status for an IP:port combination"""
    key = f"{ip}:{port}"
    with status_cache_lock:
        if key in status_cache:
            cache_time, status = status_cache[key]
            if datetime.now() - cache_time < datetime.timedelta(seconds=CACHE_DURATION):
                return status
            del status_cache[key]
    return None

def set_cached_status(ip, port, status):
    """Cache status for an IP:port combination"""
    key = f"{ip}:{port}"
    with status_cache_lock:
        status_cache[key] = (datetime.now(), status)

def check_port_status(ip, port, timeout=1):
    """
    Check if a port is open on a given IP address
    Returns: (bool, str) - (is_up, error_message)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, int(port)))
        sock.close()
        return result == 0, None
    except Exception as e:
        return False, str(e)

def check_load_balancer_status(port, ips):
    """
    Check status of all backend servers in a load balancer
    Returns: dict with status information
    """
    results = {
        'status': 'pending',
        'message': 'Checking status...',
        'all_servers_up': True,
        'server_statuses': {},
        'error': None
    }
    
    try:
        # Use fewer workers to reduce system load
        with ThreadPoolExecutor(max_workers=min(len(ips), 3)) as executor:
            future_to_ip = {
                executor.submit(check_port_status, ip, port): ip 
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_up, error = future.result()
                    results['server_statuses'][ip] = 'up' if is_up else 'down'
                    if not is_up:
                        results['all_servers_up'] = False
                except Exception as e:
                    results['server_statuses'][ip] = 'down'
                    results['all_servers_up'] = False
        
        # Set final status and message based on results
        if results['error']:
            results['status'] = 'error'
            results['message'] = f"Error checking status: {results['error']}"
        elif not results['server_statuses']:
            results['status'] = 'warning'
            results['message'] = "No servers configured"
        else:
            # Count up and down servers
            up_count = sum(1 for status in results['server_statuses'].values() if status == 'up')
            down_count = len(results['server_statuses']) - up_count
            
            if down_count == 0:  # All servers are up
                results['status'] = 'active'
                results['message'] = "All servers are up and responding"
            elif up_count == 0:  # All servers are down
                results['status'] = 'error'
                results['message'] = "All servers are down"
            else:  # Some servers are down but not all
                results['status'] = 'warning'
                results['message'] = f"{down_count} server(s) are down"
            
    except Exception as e:
        results['error'] = str(e)
        results['status'] = 'error'
        results['message'] = f"Error checking status: {str(e)}"
        results['all_servers_up'] = False
    
    return results

def cleanup_socket_pool():
    """Clean up closed sockets from the pool"""
    with socket_pool_lock:
        for key in list(socket_pool.keys()):
            if socket_pool[key]._closed:
                del socket_pool[key]

@load_balance_bp.before_request
def before_request():
    g.user = current_user
    login_manager.anonymous_user = Anonymous
    maintenance = Setting().get('maintenance')
    if maintenance and current_user.is_authenticated and current_user.role.name not in [
            'Administrator', 'Operator'
    ]:
        return render_template('maintenance.html')
    session.permanent = True
    current_app.permanent_session_lifetime = datetime.timedelta(
        minutes=int(Setting().get('session_timeout')))
    session.modified = True

@load_balance_bp.route('/', methods=['GET'])
@login_required
def dashboard():
    if not Setting().get('pdns_api_url') or \
       not Setting().get('pdns_api_key') or \
       not Setting().get('pdns_version'):
        flash('PowerDNS API settings are not configured. Please configure them first.', 'warning')
        return redirect(url_for('admin.setting_pdns'))
    
    if not (Setting().get('allow_user_view_load_balancers') or
            (current_user.is_authenticated and current_user.role.name in ['Administrator', 'Operator'])):
        current_app.logger.warning(
            f"User {current_user.username} (Role: {current_user.role.name}) "
            f"attempted to access load_balancer.dashboard without permission."
        )
        abort(403)

    domain_api = Domain()
    zones_result = domain_api.get_domains() 
    load_balancers_data = []
    
    if not zones_result:
        current_app.logger.info("No zones found via API for LB dashboard.")
        zones_result = []

    for zone_data in zones_result:
        zone_actual_name = zone_data['name'] 
        if not zone_actual_name:
            current_app.logger.warning(f"Encountered a zone with no name: {zone_data}")
            continue
        zone_info = domain_api.get_domain_info(zone_actual_name)
        if not zone_info or 'rrsets' not in zone_info:
            current_app.logger.warning(f"Could not get RRsets for zone: {zone_actual_name}, API returned: {zone_info}")
            continue
        for rrset in zone_info.get('rrsets', []):
            if rrset['type'] == 'LUA' and rrset.get('records') and rrset['records']:
                record = rrset['records'][0]
                content = record.get('content', '')
                port, ips = parse_lua_ifportup(content)
                if port is not None and ips is not None:
                    record_actual_name = rrset['name']
                    sanitized_zone = re.sub(r'[^a-zA-Z0-9_-]', '_', zone_actual_name.rstrip('.'))
                    sanitized_record = re.sub(r'[^a-zA-Z0-9_-]', '_', record_actual_name.rstrip('.'))
                    html_id = f"lb_{sanitized_zone}_{sanitized_record}"

                    # Check status of all backend servers
                    status_info = check_load_balancer_status(port, ips)
                    
                    # Check if record is disabled in PowerDNS
                    # current_app.logger.info(f'Full record data: {record}')
                    is_disabled = record.get('disabled', False)
                    # current_app.logger.info(f'Disabled state: {is_disabled}')
                    
                    # If record is disabled, override status to inactive
                    if is_disabled:
                        status_info['status'] = 'inactive'
                        status_info['message'] = 'Load balancer is disabled'
                    else:
                        # Keep the original status (active/warning/error/pending)
                        status_info['status'] = status_info.get('status', 'unknown')
                        status_info['message'] = status_info.get('message', 'Status check failed')
                    
                    lb_data = {
                        'html_id': html_id, 
                        'zone_actual_name': zone_actual_name, 
                        'record_actual_name': record_actual_name,
                        'name': record_actual_name.rstrip('.'), 
                        'zone_display_name': zone_actual_name.rstrip('.'),
                        'config_summary': f"{len(ips)} servers, port {port}, TTL {rrset['ttl']}s",
                        'status': status_info.get('status', 'unknown'),
                        'status_message': status_info.get('message', 'Status check failed'),
                        'all_servers_up': status_info.get('all_servers_up', False),
                        'server_statuses': status_info.get('server_statuses', {})
                    }
                    load_balancers_data.append(lb_data)
                else:
                    current_app.logger.info(f"Skipping LUA record {rrset['name']} in zone {zone_actual_name} due to parsing error or unrecognized format: '{content}'")

    return render_template('load_balance_dashboard.html', load_balancers=load_balancers_data)

@load_balance_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if not (Setting().get('allow_user_create_load_balance') or \
            (current_user.is_authenticated and current_user.role.name in ['Administrator', 'Operator'])):
        abort(403)

    # For fetching zone list for the dropdown
    domain_api_for_zones = Domain() # Use the Domain model/API wrapper
    zones_result = domain_api_for_zones.get_domains()
    # zone_options are like "example.com" (no trailing dot)
    zone_options = sorted([zone['name'].rstrip('.') for zone in zones_result if zone.get('name')]) if zones_result else []

    if request.method == 'POST':
        lb_record_subname = request.form.get('lb_record_subname', '').strip() # e.g., "web", "api", or "@"
        lb_zone_name = request.form.get('lb_zone_name', '').strip() # e.g., "example.com"
        lb_ttl = request.form.get('lb_ttl', '').strip()
        lb_port = request.form.get('lb_port', '').strip()
        backend_ips_form = request.form.getlist('lb_ip[]')

        errors = False
        if not lb_record_subname:
            flash('Record Name (e.g., "web", "app", or "@" for apex) for Load Balancer is required.', 'error'); errors = True
        if not lb_zone_name:
            flash('Zone (e.g., "example.com") for Load Balancer is required.', 'error'); errors = True
        if not lb_ttl or not lb_ttl.isdigit() or int(lb_ttl) < 1:
            flash('TTL must be a positive integer (e.g., 300).', 'error'); errors = True
        if not lb_port or not lb_port.isdigit() or not (1 <= int(lb_port) <= 65535):
            flash('Port must be a number between 1 and 65535.', 'error'); errors = True

        cleaned_backend_ips = [ip.strip() for ip in backend_ips_form if ip.strip()]
        if not cleaned_backend_ips:
            flash('At least one backend IP server is required.', 'error'); errors = True
        else:
            for ip_idx, ip_val in enumerate(cleaned_backend_ips):
                if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_val): # Basic IPv4 regex
                    flash(f'Invalid IP address format for IP #{ip_idx+1}: "{ip_val}". Please use IPv4 format (e.g., 192.168.1.10).', 'error'); errors = True

        if errors:
            return render_template('load_balance_add.html', request_form=request.form, zone_options=zone_options, backend_ips=backend_ips_form)

        # Prepare names for Record().apply() and for checks
        # api_record_name is the relative part, e.g., "web" or "@"
        # api_zone_name is the zone part, e.g., "example.com" (no trailing dot from form)
        api_record_name = lb_record_subname
        api_zone_name_form = lb_zone_name # This is "example.com"

        # --- PRE-EXISTENCE CHECK ---
        # Construct the FQDN of the record we intend to create (with trailing dot for API consistency)
        target_record_fqdn_display = f"{api_record_name}.{api_zone_name_form}" if api_record_name != "@" else api_zone_name_form
        target_record_fqdn_api = f"{api_record_name}.{api_zone_name_form}." if api_record_name != "@" else api_zone_name_form + "."
        
        zone_fqdn_for_check = api_zone_name_form + "." # Ensure trailing dot for get_domain_info

        domain_model_for_check = Domain() # Instance for fetching domain info
        current_app.logger.debug(f"Checking for existing LUA record '{target_record_fqdn_api}' in zone '{zone_fqdn_for_check}'")
        zone_info = domain_model_for_check.get_domain_info(zone_fqdn_for_check)

        if zone_info and 'rrsets' in zone_info:
            for rrset in zone_info.get('rrsets', []):
                # rrset['name'] from PowerDNS API is FQDN with trailing dot
                if rrset['name'] == target_record_fqdn_api and rrset['type'] == 'LUA':
                    flash(f'A Load Balancer (LUA record) named "{target_record_fqdn_display}" already exists in zone "{api_zone_name_form}". Please use the edit function or choose a different name.', 'error')
                    return render_template('load_balance_add.html',
                                           request_form=request.form,
                                           zone_options=zone_options,
                                           backend_ips=cleaned_backend_ips) # Use cleaned IPs for repopulation
        elif zone_info is None : # get_domain_info might return None on error
             flash(f'Could not retrieve information for zone "{api_zone_name_form}" to check for existing records. Please try again.', 'error')
             current_app.logger.error(f"Failed to get domain info for zone '{zone_fqdn_for_check}' during pre-existence check.")
             return render_template('load_balance_add.html',
                                   request_form=request.form,
                                   zone_options=zone_options,
                                   backend_ips=cleaned_backend_ips)
        # --- END PRE-EXISTENCE CHECK ---

        lua_content = build_lua_ifportup(lb_port, cleaned_backend_ips)

        record_api = Record()
        # Create the rrset in the format expected by PowerDNS API
        rrset = {
            "rrsets": [{
                "name": target_record_fqdn_api,
                "type": "LUA",
                "ttl": int(lb_ttl),
                "records": [{
                    "content": lua_content,
                    "disabled": False
                }],
                "comments": []
            }]
        }

        current_app.logger.info(f"Attempting to create LUA record: '{target_record_fqdn_api}' with data: {json.dumps(rrset)}")
        current_app.logger.debug(f"LUA content being sent: {lua_content}")

        try:
            # Use create() instead of apply() for creating new records
            result = record_api.create(api_zone_name_form, rrset)

            if result and result.get('status') == 'ok':
                history_msg = f'Load Balancer (LUA Record) "{target_record_fqdn_display}" created in zone "{api_zone_name_form}".'
                detail_info = {
                    "record_name": target_record_fqdn_api,
                    "zone": api_zone_name_form,
                    "ttl": lb_ttl,
                    "port": lb_port,
                    "ips": cleaned_backend_ips
                }
                # Assuming Domain().get_id_by_name(name) exists if you need domain_id
                # For now, passing None as domain_id for History
                domain_obj_for_history = Domain().get_id_by_name(api_zone_name_form)
                domain_id_for_history = domain_obj_for_history if domain_obj_for_history else None # Adjust if get_id_by_name returns dict or int

                History(msg=history_msg,
                        detail=json.dumps(detail_info),
                        created_by=current_user.username,
                        domain_id=domain_id_for_history).add()
                flash(f'Load Balancer "{target_record_fqdn_display}" created successfully!', 'success')
                return redirect(url_for('load_balance.dashboard'))
            else:
                error_msg = result.get('msg', 'Failed to create load balancer via API.') if result else 'API did not return a result.'
                current_app.logger.error(f"API error creating LUA record '{target_record_fqdn_display}': {error_msg} // API Response: {result}")
                flash(f'Error creating load balancer "{target_record_fqdn_display}": {error_msg}', 'danger')
        except Exception as e:
            current_app.logger.error(f"Exception creating LUA record '{target_record_fqdn_display}': {e}", exc_info=True)
            flash(f'An unexpected error occurred while creating "{target_record_fqdn_display}": {str(e)}', 'danger')

        return render_template('load_balance_add.html', request_form=request.form, zone_options=zone_options, backend_ips=cleaned_backend_ips)

    # GET request
    return render_template('load_balance_add.html', request_form=None, zone_options=zone_options, backend_ips=[''])


@load_balance_bp.route('/edit/<path:zone_name_dotted>/<path:record_name_dotted>', methods=['GET', 'POST'])
@login_required
def edit(zone_name_dotted, record_name_dotted):
    if not (Setting().get('allow_user_create_load_balance') or \
            (current_user.is_authenticated and current_user.role.name in ['Administrator', 'Operator'])):
        abort(403)

    domain_api = Domain() # For get_domain_info
    
    zone_name_api = zone_name_dotted + '.' if not zone_name_dotted.endswith('.') else zone_name_dotted
    record_name_api = record_name_dotted + '.' if not record_name_dotted.endswith('.') else record_name_dotted
    
    zone_info = domain_api.get_domain_info(zone_name_api)
    if not zone_info or 'rrsets' not in zone_info:
        flash(f"Error: Could not retrieve info for zone {zone_name_api.rstrip('.')}.", "danger")
        return redirect(url_for('load_balance.dashboard'))

    found_rrset = next((rrset for rrset in zone_info.get('rrsets', []) if rrset['name'] == record_name_api and rrset['type'] == 'LUA'), None)
    
    if not found_rrset or not found_rrset.get('records') or not found_rrset['records']:
        flash(f"Error: LUA record {record_name_api.rstrip('.')} not found.", "danger")
        return redirect(url_for('load_balance.dashboard'))

    original_content = found_rrset['records'][0].get('content', '')
    original_port, original_ips = parse_lua_ifportup(original_content)
    original_ttl = found_rrset['ttl']
    original_disabled = found_rrset['records'][0].get('disabled', False)
    original_comments = found_rrset.get('comments', [])

    if original_port is None or original_ips is None:
        flash(f"Error: Could not parse LUA content for {record_name_api.rstrip('.')}. Content: '{original_content}'", "danger")
        return redirect(url_for('load_balance.dashboard'))

    if request.method == 'POST':
        lb_ttl = request.form.get('lb_ttl', '').strip()
        lb_port = request.form.get('lb_port', '').strip()
        backend_ips_form = request.form.getlist('lb_ip[]')
        errors = False
        if not lb_ttl or not lb_ttl.isdigit() or int(lb_ttl) < 1: flash('TTL must be a positive integer.', 'error'); errors = True
        if not lb_port or not lb_port.isdigit() or not (1 <= int(lb_port) <= 65535): flash('Port must be a number between 1 and 65535.', 'error'); errors = True
        cleaned_backend_ips = [ip.strip() for ip in backend_ips_form if ip.strip()]
        if not cleaned_backend_ips: flash('At least one backend IP server is required.', 'error'); errors = True
        else:
            for ip_idx, ip_val in enumerate(cleaned_backend_ips):
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_val):
                     flash(f'Invalid IP address format for IP #{ip_idx+1}: "{ip_val}".', 'error'); errors = True
        if errors:
            return render_template('load_balance_edit.html', zone_name_dotted=zone_name_dotted, record_name_dotted=record_name_dotted,
                                 lb_name_display=record_name_api.rstrip('.'), lb_ttl=lb_ttl, lb_port=lb_port, backend_ips=backend_ips_form)

        new_lua_content = build_lua_ifportup(lb_port, cleaned_backend_ips)
        
        # Extract just the subdomain part
        subdomain = extract_subdomain(record_name_api.rstrip('.'), zone_name_api.rstrip('.'))
        
        record_api = Record() 
        record_to_apply = [{
            'record_name': subdomain,  # Use just the subdomain part
            'record_type': "LUA",
            'record_ttl': int(lb_ttl),
            'record_data': new_lua_content,
            'record_status': 'Disabled' if original_disabled else 'Active', # Preserve disabled state
            'comment_data': original_comments # Preserve comments
        }]
        
        # current_app.logger.info(f"Attempting to apply update for LUA record: {record_name_api} in zone {zone_name_api} with data: {json.dumps(record_to_apply)}")
        
        try:
            result = record_api.apply(zone_name_api.rstrip('.'), record_to_apply) # Zone name without trailing dot

            if result and result.get('status') == 'ok':
                history_msg = f'Load Balancer (LUA Record) "{record_name_api.rstrip(".")}" in zone "{zone_name_api.rstrip(".")}" updated.'
                detail_info = {
                    "record_name": record_name_api, "zone": zone_name_api,
                    "new_ttl": lb_ttl, "new_port": lb_port, "new_ips": cleaned_backend_ips,
                    "old_ttl": original_ttl, "old_port": original_port, "old_ips": original_ips
                }
                History(msg=history_msg, detail=json.dumps(detail_info), created_by=current_user.username, domain_id=None).add()
                flash(f'Load Balancer "{record_name_api.rstrip(".")}" updated successfully!', 'success')
                return redirect(url_for('load_balance.dashboard'))
            else:
                error_msg = result.get('msg', 'Failed to apply load balancer update via API.') if result else 'API did not return a result.'
                current_app.logger.error(f"API error applying LUA record update {record_name_api}: {error_msg} // API Response: {result}")
                flash(f'Error processing load balancer update: {error_msg}', 'danger')
        except Exception as e:
            current_app.logger.error(f"Exception applying LUA record update {record_name_api}: {e}", exc_info=True)
            flash(f'An unexpected error occurred: {str(e)}', 'danger')

        return render_template('load_balance_edit.html', zone_name_dotted=zone_name_dotted, record_name_dotted=record_name_dotted,
                             lb_name_display=record_name_api.rstrip('.'), lb_ttl=lb_ttl, lb_port=lb_port, backend_ips=backend_ips_form)

    return render_template('load_balance_edit.html', zone_name_dotted=zone_name_dotted, record_name_dotted=record_name_dotted,
                         lb_name_display=record_name_api.rstrip('.'), lb_ttl=original_ttl, lb_port=original_port, backend_ips=original_ips)


@load_balance_bp.route('/delete/<path:zone_name_dotted>/<path:record_name_dotted>', methods=['POST'])
@login_required
@operator_role_required
def delete_lb(zone_name_dotted, record_name_dotted):
    # Add debug logging
    current_app.logger.info(f"Delete request from user: {current_user.username}")
    current_app.logger.info(f"User role: {current_user.role.name}")
    current_app.logger.info(f"User authenticated: {current_user.is_authenticated}")
    current_app.logger.info(f"User ID: {current_user.id}")
    
    zone_name_api = zone_name_dotted + '.' if not zone_name_dotted.endswith('.') else zone_name_dotted
    record_name_api = record_name_dotted + '.' if not record_name_dotted.endswith('.') else record_name_dotted

    current_app.logger.info(f"Attempting to delete LUA Record: {record_name_api} in zone {zone_name_api} by user {current_user.username}")

    try:
        record_api = Record()
        # Set record name and type before calling delete
        record_api.name = record_name_api
        record_api.type = "LUA"
        
        result = record_api.delete(zone_name_api)

        if result and result.get('status') == 'ok':
            history_msg = f'Load Balancer (LUA Record) "{record_name_api.rstrip(".")}" in zone "{zone_name_api.rstrip(".")}" deleted.'
            detail_info = {
                "record_name": record_name_api,
                "zone": zone_name_api
            }
            History(msg=history_msg, detail=json.dumps(detail_info), created_by=current_user.username, domain_id=None).add()
            
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'ok'})
            return redirect(url_for('load_balance.dashboard'))
        else:
            error_msg = result.get('msg', 'Failed to delete load balancer via API.') if result else 'No response from API call attempt.'
            current_app.logger.error(f"Failed to delete LUA record {record_name_api}. API Call Result: {result}")
            
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'msg': error_msg}), 500
            flash(f'Error deleting load balancer: {error_msg}', 'danger')
            return redirect(url_for('load_balance.dashboard'))
    except Exception as e:
        current_app.logger.error(f"Exception during API call for delete_lb ({record_name_api}): {e}", exc_info=True)
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'msg': str(e)}), 500
        flash(f'Error deleting load balancer: {str(e)}', 'danger')
        return redirect(url_for('load_balance.dashboard'))


@load_balance_bp.route('/view/<path:zone_name_dotted>/<path:record_name_dotted>', methods=['GET'])
@login_required
def view(zone_name_dotted, record_name_dotted):
    if not (Setting().get('allow_user_view_load_balancers') or \
            (current_user.is_authenticated and current_user.role.name in ['Administrator', 'Operator'])):
        abort(403)
    if not zone_name_dotted.endswith('.'): zone_name_api = zone_name_dotted + '.'
    else: zone_name_api = zone_name_dotted
    if not record_name_dotted.endswith('.'): record_name_api = record_name_dotted + '.'
    else: record_name_api = record_name_dotted
    domain_api = Domain()
    zone_info = domain_api.get_domain_info(zone_name_api)
    if not zone_info or 'rrsets' not in zone_info:
        flash(f"Error: Could not retrieve data for zone {zone_name_api.rstrip('.')}.", "danger")
        return redirect(url_for('load_balance.dashboard'))
    found_rrset = next((rrset for rrset in zone_info.get('rrsets', []) if rrset['name'] == record_name_api and rrset['type'] == 'LUA'), None)
    if not found_rrset or not found_rrset.get('records') or not found_rrset['records']:
        flash(f"LUA record {record_name_api.rstrip('.')} not found.", "danger")
        return redirect(url_for('load_balance.dashboard'))
    record = found_rrset['records'][0]
    content = record.get('content', '')
    port, ips = parse_lua_ifportup(content)
    if port is None or ips is None:
        flash(f"Error parsing LUA record content for {record_name_api.rstrip('.')}. Content: '{content}'", "danger")
        return redirect(url_for('load_balance.dashboard'))
    
    # Check status of backend servers
    status_info = check_load_balancer_status(port, ips)
    
    load_balancer_details = {
        'zone_actual_name': zone_name_api, 'record_actual_name': record_name_api,
        'name': record_name_api.rstrip('.'), 'zone_display_name': zone_name_api.rstrip('.'),
        'ttl': found_rrset['ttl'], 'port': port, 'backend_servers_ips': ips,
        'config_summary': f"{len(ips)} servers, port {port}, TTL {found_rrset['ttl']}s",
        'status': status_info.get('status', 'unknown'),
        'status_message': status_info.get('message', 'Status unknown'),
        'server_statuses': status_info.get('server_statuses', {}),
        'comments': found_rrset.get('comments', []), 'raw_content': content,
        'backend_servers': [{'address': ip} for ip in ips] # Simplified for view
    }
    return render_template('load_balance_view.html', load_balancer=load_balancer_details)

def update_load_balancer_status():
    """
    Update status of all load balancers
    """
    domain_api = Domain()
    zones_result = domain_api.get_domains()
    
    if not zones_result:
        current_app.logger.info("No zones found for load balancer status update")
        return
    
    for zone_data in zones_result:
        zone_actual_name = zone_data['name']
        if not zone_actual_name:
            continue
            
        zone_info = domain_api.get_domain_info(zone_actual_name)
        if not zone_info or 'rrsets' not in zone_info:
            continue
            
        for rrset in zone_info.get('rrsets', []):
            if rrset['type'] == 'LUA' and rrset.get('records') and rrset['records']:
                record = rrset['records'][0]
                content = record.get('content', '')
                port, ips = parse_lua_ifportup(content)
                
                if port is not None and ips is not None:
                    # Check status of all backend servers
                    status = check_load_balancer_status(port, ips)
                    
                    # Update record status based on check results
                    if status['all_servers_up']:
                        record['disabled'] = False
                    else:
                        record['disabled'] = True
                    
                    # Update the record in PowerDNS
                    record_api = Record()
                    record_to_apply = [{
                        'record_name': extract_subdomain(rrset['name'].rstrip('.'), zone_actual_name.rstrip('.')),
                        'record_type': "LUA",
                        'record_ttl': rrset['ttl'],
                        'record_data': content,
                        'record_status': 'Disabled' if record['disabled'] else 'Active',
                        'comment_data': rrset.get('comments', [])
                    }]
                    
                    try:
                        result = record_api.apply(zone_actual_name.rstrip('.'), record_to_apply)
                        if result and result.get('status') == 'ok':
                            current_app.logger.info(f"Updated load balancer status for {rrset['name']} in zone {zone_actual_name}")
                        else:
                            current_app.logger.error(f"Failed to update load balancer status for {rrset['name']} in zone {zone_actual_name}")
                    except Exception as e:
                        current_app.logger.error(f"Error updating load balancer status: {str(e)}")

@load_balance_bp.route('/status/update', methods=['POST'])
@login_required
def update_status():
    """
    Update and return the status of all load balancers.
    """
    if not (Setting().get('allow_user_view_load_balancers') or \
            (current_user.is_authenticated and current_user.role.name in ['Administrator', 'Operator'])):
        abort(403)
    
    try:
        # Get CSRF token from JSON data
        csrf_token = request.json.get('csrf_token')
        if not csrf_token:
            return jsonify({
                'status': 'error',
                'msg': 'Missing CSRF token'
            }), 400

        update_load_balancer_status()
        cleanup_socket_pool()  # Clean up socket pool after update

        return jsonify({
            'status': 'ok',
            'msg': 'Load balancer statuses have been updated successfully.'
        })

    except Exception as e:
        current_app.logger.error(f"Error updating load balancer statuses: {str(e)}")
        return jsonify({
            'status': 'error',
            'msg': f'Error updating load balancer statuses: {str(e)}'
        }), 500

@load_balance_bp.route('/status/check/<path:zone_name_dotted>/<path:record_name_dotted>', methods=['GET'])
@login_required
def check_status(zone_name_dotted, record_name_dotted):
    """
    Check and return the current status of a specific load balancer
    """
    if not (Setting().get('allow_user_view_load_balancers') or \
            (current_user.is_authenticated and current_user.role.name in ['Administrator', 'Operator'])):
        abort(403)
    
    zone_name_api = zone_name_dotted + '.' if not zone_name_dotted.endswith('.') else zone_name_dotted
    record_name_api = record_name_dotted + '.' if not record_name_dotted.endswith('.') else record_name_dotted
    
    domain_api = Domain()
    zone_info = domain_api.get_domain_info(zone_name_api)
    
    if not zone_info or 'rrsets' not in zone_info:
        return jsonify({
            'status': 'error',
            'message': f"Could not retrieve info for zone {zone_name_api.rstrip('.')}"
        }), 404
    
    found_rrset = next((rrset for rrset in zone_info.get('rrsets', []) 
                       if rrset['name'] == record_name_api and rrset['type'] == 'LUA'), None)
    
    if not found_rrset or not found_rrset.get('records') or not found_rrset['records']:
        return jsonify({
            'status': 'error',
            'message': f"LUA record {record_name_api.rstrip('.')} not found"
        }), 404
    
    record = found_rrset['records'][0]
    content = record.get('content', '')
    port, ips = parse_lua_ifportup(content)
    
    if port is None or ips is None:
        return jsonify({
            'status': 'error',
            'message': f"Could not parse LUA content for {record_name_api.rstrip('.')}"
        }), 400
    
    status = check_load_balancer_status(port, ips)
    
    return jsonify({
        'status': 'success',
        'data': {
            'record_name': record_name_api.rstrip('.'),
            'zone_name': zone_name_api.rstrip('.'),
            'port': port,
            'servers': status['server_statuses'],
            'all_up': status['all_servers_up'],
            'error': status['error']
        }
    })

@load_balance_bp.route('/toggle-status/<path:zone_name_dotted>/<path:record_name_dotted>', methods=['POST'])
@login_required
@operator_role_required
def toggle_status(zone_name_dotted, record_name_dotted):
    try:
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'status': 'error', 'msg': 'Missing status parameter'}), 400

        # Verify CSRF token
        if not request.headers.get('X-CSRF-Token') and not request.headers.get('X-CSRFToken'):
            return jsonify({'status': 'error', 'msg': 'CSRF token missing'}), 403

        new_status = data['status']
        if new_status not in ['active', 'disabled']:
            return jsonify({'status': 'error', 'msg': 'Invalid status value'}), 400

        # Get the record
        record_api = Record()
        zone_name = zone_name_dotted.rstrip('.')
        record_name = record_name_dotted.rstrip('.')
        
        # current_app.logger.info(f'Zone name: {zone_name}')
        # current_app.logger.info(f'Record name: {record_name}')
        
        # Get zone records
        rrsets = record_api.get_rrsets(zone_name)
        
        # Find the specific record
        target_record = None
        for rrset in rrsets:
            if rrset['name'].rstrip('.') == record_name:
                target_record = rrset
                break
        
        if not target_record:
            return jsonify({'status': 'error', 'msg': 'Load balancer not found'}), 404

        # Create the rrset for updating
        rrset = {
            "rrsets": [{
                "name": f"{record_name}.",
                "type": target_record['type'],
                "ttl": target_record['ttl'],
                "changetype": "REPLACE",
                "records": [{
                    "content": target_record['records'][0]['content'],
                    "disabled": new_status == 'disabled'
                }],
                "comments": target_record.get('comments', [])
            }]
        }

        # current_app.logger.info(f'rrset: {rrset}')

        # Apply the changes
        headers = {'X-API-Key': record_api.PDNS_API_KEY, 'Content-Type': 'application/json'}
        try:
            result = utils.fetch_json(
                urljoin(
                    record_api.PDNS_STATS_URL,
                    f"{record_api.API_EXTENDED_URL}/servers/localhost/zones/{zone_name}"
                ),
                headers=headers,
                method='PATCH',
                verify=Setting().get('verify_ssl_connections'),
                data=rrset
            )
            
            if 'error' in result:
                current_app.logger.error(f"Failed to toggle load balancer status: {result['error']}")
                return jsonify({'status': 'error', 'msg': str(result['error'])}), 500

            # Update the database serial
            record_api.update_db_serial(zone_name)
            
            # current_app.logger.info(f"Toggled load balancer status to {new_status} for {record_name_dotted} in zone {zone_name_dotted}")
            return jsonify({
                'status': 'ok',
                'msg': f'Load balancer {new_status}',
                'display_status': 'Inactive' if new_status == 'disabled' else None  # None means keep original status
            })
        except Exception as e:
            current_app.logger.error(f"Failed to toggle load balancer status: {str(e)}")
            return jsonify({'status': 'error', 'msg': str(e)}), 500

    except Exception as e:
        current_app.logger.error(f"Error toggling load balancer status: {str(e)}")
        return jsonify({'status': 'error', 'msg': str(e)}), 500

# --- HELPER FUNCTIONS ---
def parse_lua_ifportup(content_str):
    if not content_str: return None, None
    match = re.match(r"ifportup\s*\(\s*(\d+)\s*,\s*\{(.*?)\}\s*\)", content_str, re.IGNORECASE)
    if not match:
        # current_app.logger.warning(f"Could not parse LUA content: {content_str} with regex.")
        if "ifportup(" in content_str and "," in content_str and "{" in content_str and "}" in content_str:
            try:
                port_part = content_str.split('(')[1].split(',')[0].strip()
                ips_part = content_str.split('{')[1].split('}')[0].strip()
                ips_list = [ip.strip().strip("'\"") for ip in ips_part.split(',') if ip.strip()]
                if port_part.isdigit() and (ips_list or not ips_part):
                    # current_app.logger.info(f"Lenient parsing succeeded for: {content_str}")cl
                    return port_part, ips_list
            except Exception as e:
                # current_app.logger.error(f"Lenient parsing failed for {content_str}: {e}")
                return None, None
        return None, None
    port_str, ips_group_str = match.groups()
    ips_list = [ip.strip().strip("'\"") for ip in ips_group_str.split(',') if ip.strip()] if ips_group_str.strip() else []
    return port_str, ips_list

def build_lua_ifportup(port, ips_list):
    if not isinstance(ips_list, list): return ""
    cleaned_ips = [str(ip).strip().strip("'\"") for ip in ips_list if str(ip).strip()]
    quoted_ips = [f"'{ip}'" for ip in cleaned_ips]
    # Return LUA content in the correct format for PowerDNS
    return f'A "ifportup({port}, {{{",".join(quoted_ips)}}})"'

def extract_subdomain(full_name, zone_name):
    """Extract just the subdomain part from a full record name."""
    if not full_name or not zone_name:
        return full_name
    # Remove trailing dots and convert to lowercase for comparison
    full_name = full_name.rstrip('.').lower()
    zone_name = zone_name.rstrip('.').lower()
    # If the full name ends with the zone name, remove it
    if full_name.endswith(zone_name):
        subdomain = full_name[:-len(zone_name)].rstrip('.')
        return subdomain
    return full_name