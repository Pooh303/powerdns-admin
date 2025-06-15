import re
import traceback
import dns.reversename
import dns.inet
import dns.name
from flask import current_app
from urllib.parse import urljoin
from distutils.util import strtobool
from itertools import groupby

from .. import utils
from .base import db
from .setting import Setting
from .domain import Domain
from .domain_setting import DomainSetting


def by_record_content_pair(e):
    return e[0]['content']


class Record(object):
    def __init__(self,
                 name=None,
                 type=None,
                 status=None,
                 ttl=None,
                 data=None,
                 comment_data=None):
        self.name = name
        self.type = type
        self.status = status
        self.ttl = ttl
        self.data = data
        self.comment_data = comment_data
        self.PDNS_STATS_URL = Setting().get('pdns_api_url')
        self.PDNS_API_KEY = Setting().get('pdns_api_key')
        self.PDNS_VERSION = Setting().get('pdns_version')
        self.API_EXTENDED_URL = utils.pdns_api_extended_uri(self.PDNS_VERSION)
        self.PRETTY_IPV6_PTR = Setting().get('pretty_ipv6_ptr')

    def get_rrsets(self, domain):
        headers = {'X-API-Key': self.PDNS_API_KEY}
        try:
            jdata = utils.fetch_json(urljoin(
                self.PDNS_STATS_URL, self.API_EXTENDED_URL +
                '/servers/localhost/zones/{0}'.format(domain)),
                                     timeout=int(
                                         Setting().get('pdns_api_timeout')),
                                     headers=headers,
                                     verify=Setting().get('verify_ssl_connections'))
        except Exception as e:
            current_app.logger.error(
                "Cannot fetch zone's record data from remote powerdns api. DETAIL: {0}"
                .format(e))
            return []

        rrsets=[]
        for r in jdata['rrsets']:
            if len(r['records']) == 0:
                continue
            while len(r['comments'])<len(r['records']):
                r['comments'].append({"content": "", "account": ""})
            r['records'], r['comments'] = (list(t) for t in zip(*sorted(zip(r['records'], r['comments']), key=by_record_content_pair)))
            rrsets.append(r)
        return rrsets

    def add(self, domain_name, rrset):
        rrsets = self.get_rrsets(domain_name)
        check = list(filter(lambda check: check['name'] == self.name, rrsets))
        if check:
            r = check[0]
            if r['type'] in ('A', 'AAAA', 'CNAME'):
                return {
                    'status': 'error',
                    'msg':
                    'Record already exists with type "A", "AAAA" or "CNAME"'
                }
        headers = {'X-API-Key': self.PDNS_API_KEY, 'Content-Type': 'application/json'}
        try:
            jdata = utils.fetch_json(urljoin(
                self.PDNS_STATS_URL, self.API_EXTENDED_URL +
                '/servers/localhost/zones/{0}'.format(domain_name)),
                                     headers=headers,
                                     timeout=int(
                                         Setting().get('pdns_api_timeout')),
                                     method='PATCH',
                                     verify=Setting().get('verify_ssl_connections'),
                                     data=rrset)
            # current_app.logger.debug(jdata)
            return {'status': 'ok', 'msg': 'Record was added successfully'}
        except Exception as e:
            current_app.logger.error(
                "Cannot add record to zone {}. Error: {}".format(
                    domain_name, e))
            # current_app.logger.debug("Submitted record rrset: \n{}".format(
            #     utils.pretty_json(rrset)))
            return {
                'status': 'error',
                'msg':
                'There was something wrong, please contact administrator'
            }

    def merge_rrsets(self, rrsets):
        if not rrsets:
            raise Exception("Empty rrsets to merge")
        elif len(rrsets) == 1:
            return rrsets[0]
        else:
            rrset = rrsets[0]
            for r in rrsets[1:]:
                rrset['records'] = rrset['records'] + r['records']
                rrset['comments'] = rrset['comments'] + r['comments']
            while len(rrset['comments']) < len(rrset['records']):
                rrset['comments'].append({"content": "", "account": ""})
            zipped_list = zip(rrset['records'], rrset['comments'])
            tuples = zip(*sorted(zipped_list, key=by_record_content_pair))
            rrset['records'], rrset['comments'] = [list(t) for t in tuples]
            return rrset

    def build_rrsets(self, domain_name, submitted_records):
        rrsets = []
        for record in submitted_records:
            record['record_data'] = record['record_data'].replace('[ZONE]', domain_name)
            record['record_name'] = utils.to_idna(record["record_name"], "encode")
            if record['record_type'] == 'CNAME' or record['record_type'] == 'SOA':
                record['record_data'] = utils.to_idna(record['record_data'], 'encode')
            if self.PRETTY_IPV6_PTR and re.search(
                    r'ip6\.arpa', domain_name
            ) and record['record_type'] == 'PTR' and ':' in record[
                    'record_name']:
                record_name = dns.reversename.from_address(
                    record['record_name']).to_text()
            else:
                record_name = "{}.{}.".format(
                    record["record_name"],
                    domain_name) if record["record_name"] not in [
                        '@', ''
                    ] else domain_name + '.'
            if record["record_type"] in [
                    'MX', 'CNAME', 'SRV', 'NS', 'PTR'
            ] and record["record_data"].strip()[-1:] != '.':
                record["record_data"] += '.'
            record_content = {
                "content": record["record_data"],
                "disabled":
                False if record['record_status'] == 'Active' else True
            }
            record_comments = [{
                "content": record["record_comment"],
                "account": ""
            }] if record.get("record_comment") else [{
                "content": "",
                "account": ""
            }]
            rrsets.append({
                "name": record_name,
                "type": record["record_type"],
                "ttl": int(record["record_ttl"]),
                "records": [record_content],
                "comments": record_comments
            })
        transformed_rrsets = []
        rrsets = sorted(rrsets, key=lambda r: (r['name'], r['type']))
        groups = groupby(rrsets, key=lambda r: (r['name'], r['type']))
        for _k, v in groups:
            group = list(v)
            transformed_rrsets.append(self.merge_rrsets(group))
        return transformed_rrsets

    def compare(self, domain_name, submitted_records):
        submitted_rrsets = self.build_rrsets(domain_name, submitted_records)
        # current_app.logger.debug(
        #     "compare: submitted_rrsets_data (from current form submission): \n{}".format(utils.pretty_json(submitted_rrsets)))

        current_rrsets_from_pdns = self.get_rrsets(domain_name)
        # current_app.logger.debug("compare: current_rrsets_from_pdns (all records in zone): \n{}".format(
        #     utils.pretty_json(current_rrsets_from_pdns)))

        zone_has_comments = False
        for r_pdns in current_rrsets_from_pdns:
            for comment in r_pdns.get('comments', []):
                if 'modified_at' in comment:
                    zone_has_comments = True
                    del comment['modified_at']

        new_or_updated_rrsets_list = []
        
        for submitted_r in submitted_rrsets:
            if submitted_r['type'] not in Setting().get_records_allow_to_edit():
                # current_app.logger.warning(f"compare: Submitted record type {submitted_r['type']} for {submitted_r['name']} is not allowed to be edited. Skipping.")
                continue

            existing_r_in_pdns = None
            for current_r_pdns in current_rrsets_from_pdns:
                if submitted_r['name'] == current_r_pdns['name'] and \
                   submitted_r['type'] == current_r_pdns['type']:
                    existing_r_in_pdns = current_r_pdns
                    break
            
            needs_update_or_is_new = False
            if existing_r_in_pdns:
                if int(submitted_r['ttl']) != int(existing_r_in_pdns['ttl']):
                    needs_update_or_is_new = True
                
                submitted_records_data = sorted([{"content": rec['content'], "disabled": rec['disabled']} for rec in submitted_r['records']], key=lambda x: x['content'])
                existing_records_data = sorted([{"content": rec['content'], "disabled": rec['disabled']} for rec in existing_r_in_pdns['records']], key=lambda x: x['content'])
                if submitted_records_data != existing_records_data:
                    needs_update_or_is_new = True

                submitted_comments = sorted([c for c in submitted_r.get('comments', []) if c.get('content')], key=lambda x: x['content']) if submitted_r.get('comments') else []
                existing_comments = sorted([c for c in existing_r_in_pdns.get('comments', []) if c.get('content')], key=lambda x: x['content']) if existing_r_in_pdns.get('comments') else []
                if submitted_comments != existing_comments:
                    needs_update_or_is_new = True

                if needs_update_or_is_new:
                    # current_app.logger.info(f"compare: Record {submitted_r['name']}/{submitted_r['type']} marked for REPLACE due to changes.")
                    submitted_r['changetype'] = 'REPLACE'
                    new_or_updated_rrsets_list.append(submitted_r)
                else:
                    # current_app.logger.info(f"compare: Record {submitted_r['name']}/{submitted_r['type']} has no changes. Skipping.")
                    pass
            else: # Is a new record
                # current_app.logger.info(f"compare: Record {submitted_r['name']}/{submitted_r['type']} is new. Marked for REPLACE.")
                submitted_r['changetype'] = 'REPLACE'
                new_or_updated_rrsets_list.append(submitted_r)

        del_rrsets_list = []
        for r_pdns in current_rrsets_from_pdns:
            if r_pdns['type'] in Setting().get_records_allow_to_edit() and \
               r_pdns['type'] != 'SOA':
                is_in_submission = False
                for submitted_r_check in submitted_rrsets:
                    if r_pdns['name'] == submitted_r_check['name'] and \
                       r_pdns['type'] == submitted_r_check['type']:
                        is_in_submission = True
                        break
                if not is_in_submission:
                    # current_app.logger.info(f"compare: Record {r_pdns['name']}/{r_pdns['type']} exists in PDNS but not in current submission. Marking for DELETE.")
                    r_pdns['changetype'] = 'DELETE'
                    del_rrsets_list.append(r_pdns)

        new_or_updated_rrsets_dict = {"rrsets": new_or_updated_rrsets_list}
        del_rrsets_dict = {"rrsets": del_rrsets_list}

        # current_app.logger.debug("compare: new_or_updated_rrsets: \n{}".format(utils.pretty_json(new_or_updated_rrsets_dict)))
        # current_app.logger.debug("compare: del_rrsets: \n{}".format(utils.pretty_json(del_rrsets_dict)))

        return new_or_updated_rrsets_dict, del_rrsets_dict, zone_has_comments

    def apply_rrsets(self, domain_name, rrsets):
        headers = {'X-API-Key': self.PDNS_API_KEY, 'Content-Type': 'application/json'}
        jdata = utils.fetch_json(urljoin(
            self.PDNS_STATS_URL, self.API_EXTENDED_URL +
            '/servers/localhost/zones/{0}'.format(domain_name)),
                                  headers=headers,
                                  method='PATCH',
                                  verify=Setting().get('verify_ssl_connections'),
                                  data=rrsets)
        return jdata

    @staticmethod
    def to_api_payload(new_rrsets_list, del_rrsets_list, comments_supported):
        if not isinstance(new_rrsets_list, list): new_rrsets_list = []
        if not isinstance(del_rrsets_list, list): del_rrsets_list = []

        def replace_for_api(rrset):
            if not rrset: return rrset # Should not happen
            if rrset.get('changetype') != 'REPLACE':
                # current_app.logger.warning(f"to_api_payload: rrset for replace without REPLACE changetype: {rrset.get('name')}")
                rrset['changetype'] = 'REPLACE'
            replace_copy = dict(rrset)
            has_nonempty_comments = any(bool(c.get('content', None)) for c in replace_copy.get('comments', []))
            if not has_nonempty_comments:
                if comments_supported:
                    replace_copy['comments'] = []
                else:
                    replace_copy.pop('comments', None)
            return replace_copy

        def rrset_in(needle_name, needle_type, haystack_list):
            for hay in haystack_list:
                if needle_name == hay['name'] and needle_type == hay['type']:
                    return True
            return False

        def delete_for_api(rrset):
            if not rrset or rrset.get('changetype') != 'DELETE': return rrset
            delete_copy = dict(rrset)
            delete_copy.pop('ttl', None)
            delete_copy.pop('records', None)
            delete_copy.pop('comments', None)
            return delete_copy

        final_deletes_for_api = []
        for r_del in del_rrsets_list:
            if not rrset_in(r_del['name'], r_del['type'], new_rrsets_list):
                final_deletes_for_api.append(delete_for_api(r_del))
            else:
                # current_app.logger.debug(f"to_api_payload: Skipping delete for {r_del['name']}/{r_del['type']} as it's being replaced.")
                pass
        
        replaces_for_api = [replace_for_api(r_new) for r_new in new_rrsets_list]
        combined_rrsets = final_deletes_for_api + replaces_for_api
        return {'rrsets': combined_rrsets}

    def apply(self, domain_name, submitted_records_from_caller):
        # current_app.logger.debug(
        #     "apply: submitted_records_from_caller: {}".format(submitted_records_from_caller))

        new_or_updated_rrsets, del_rrsets_from_compare, zone_has_comments = self.compare(domain_name, submitted_records_from_caller)
        
        final_del_rrsets_for_api = []
        is_single_record_context = len(submitted_records_from_caller) == 1

        if not is_single_record_context:
            final_del_rrsets_for_api = del_rrsets_from_compare['rrsets']
            # current_app.logger.info("apply: Multi-record context. Using deletions from compare().")
        else:
            # current_app.logger.info("apply: Single-record context. Ignoring compare() deletions for other records.")
            pass

        api_payload = self.to_api_payload(
            new_or_updated_rrsets['rrsets'],
            final_del_rrsets_for_api,
            zone_has_comments
        )
        # current_app.logger.debug(f"apply: final api_payload: \n{utils.pretty_json(api_payload)}")

        try:
            if api_payload["rrsets"]:
                result = self.apply_rrsets(domain_name, api_payload)
                if 'error' in result:
                    current_app.logger.error(
                        'Cannot apply record changes. PDNS error: {}'.format(result['error']))
                    return {
                        'status': 'error',
                        'msg': str(result['error']).replace("'", "")
                    }
            else:
                # current_app.logger.info("apply: No changes in api_payload. Skipping API call.")
                return {'status': 'ok', 'msg': 'No changes needed for the record.', 'data': ({"rrsets":[]}, {"rrsets":[]})}
            
            # self.auto_ptr(domain_name, new_or_updated_rrsets, del_rrsets_from_compare) # Consider if needed for LUA
            self.update_db_serial(domain_name)
            # current_app.logger.info('Record changes were processed successfully.')
            return {'status': 'ok', 'msg': 'Record changes were processed successfully', 'data': (new_or_updated_rrsets, {"rrsets": final_del_rrsets_for_api})}
        except Exception as e:
            current_app.logger.error(
                "Cannot apply record changes to zone {0}. Error: {1}".format(
                    domain_name, e))
            # current_app.logger.debug(traceback.format_exc())
            return {
                'status': 'error',
                'msg': 'There was something wrong, please contact administrator'
            }

    def auto_ptr(self, domain_name, new_rrsets, del_rrsets):
        auto_ptr_enabled = False
        if Setting().get('auto_ptr'):
            auto_ptr_enabled = True
        else:
            domain_obj = Domain.query.filter(Domain.name == domain_name).first()
            domain_setting = DomainSetting.query.filter(
                DomainSetting.domain == domain_obj).filter(
                    DomainSetting.setting == 'auto_ptr').first()
            auto_ptr_enabled = strtobool(
                domain_setting.value) if domain_setting else False

        if auto_ptr_enabled:
            try:
                RECORD_TYPE_TO_PTR = ['A', 'AAAA']
                new_rrsets = new_rrsets['rrsets']
                del_rrsets = del_rrsets['rrsets']
                if not new_rrsets and not del_rrsets:
                    # current_app.logger.info('No changes detected. Skipping auto ptr...')
                    return {'status': 'ok', 'msg': 'No changes detected. Skipping auto ptr...'}
                new_rrsets = [r for r in new_rrsets if r['type'] in RECORD_TYPE_TO_PTR]
                del_rrsets = [r for r in del_rrsets if r['type'] in RECORD_TYPE_TO_PTR]
                d = Domain()
                for r in del_rrsets:
                    for record in r['records']:
                        reverse_host_address = dns.reversename.from_address(record['content']).to_text()
                        domain_reverse_name = d.get_reverse_domain_name(reverse_host_address)
                        d.create_reverse_domain(domain_name, domain_reverse_name)
                        self.name = reverse_host_address
                        self.type = 'PTR'
                        self.data = record['content']
                        self.delete(domain_reverse_name)
                for r in new_rrsets:
                    for record in r['records']:
                        reverse_host_address = dns.reversename.from_address(record['content']).to_text()
                        domain_reverse_name = d.get_reverse_domain_name(reverse_host_address)
                        d.create_reverse_domain(domain_name, domain_reverse_name)
                        rrset_data = [{"changetype": "REPLACE", "name": reverse_host_address, "ttl": r['ttl'], "type": "PTR", "records": [{"content": r['name'], "disabled": record['disabled']}], "comments": []}]
                        rrset = {"rrsets": rrset_data}
                        self.add(domain_reverse_name, rrset)
                return {'status': 'ok', 'msg': 'Auto-PTR record was updated successfully'}
            except Exception as e:
                current_app.logger.error(f"Cannot update auto-ptr record changes to zone {domain_name}. Error: {e}")
                # current_app.logger.debug(traceback.format_exc())
                return {'status': 'error', 'msg': 'Auto-PTR creation failed.'}
        return {'status': 'ok', 'msg': 'Auto-PTR not enabled or no relevant records.'}

    def delete(self, domain):
        headers = {'X-API-Key': self.PDNS_API_KEY, 'Content-Type': 'application/json'}
        data = {"rrsets": [{"name": self.name.rstrip('.') + '.', "type": self.type, "changetype": "DELETE", "records": []}]}
        try:
            jdata = utils.fetch_json(urljoin(
                self.PDNS_STATS_URL, self.API_EXTENDED_URL +
                '/servers/localhost/zones/{0}'.format(domain)),
                                     headers=headers,
                                     timeout=int(Setting().get('pdns_api_timeout')),
                                     method='PATCH',
                                     verify=Setting().get('verify_ssl_connections'),
                                     data=data)
            # current_app.logger.debug(jdata)
            return {'status': 'ok', 'msg': 'Record was removed successfully'}
        except Exception as e:
            current_app.logger.error(f"Cannot remove record {self.name}/{self.type}/{self.data} from zone {domain}. DETAIL: {e}")
            return {'status': 'error', 'msg': 'There was something wrong, please contact administrator'}

    def is_allowed_edit(self):
        return self.type in Setting().get_records_allow_to_edit()

    def is_allowed_delete(self):
        return (self.type in Setting().get_records_allow_to_edit() and self.type != 'SOA')

    def exists(self, domain):
        rrsets = self.get_rrsets(domain)
        for r in rrsets:
            if r['name'].rstrip('.') == self.name and r['type'] == self.type and r['records']:
                self.type = r['type']
                self.status = r['records'][0]['disabled']
                self.ttl = r['ttl']
                self.data = r['records'][0]['content']
                return True
        return False

    def update(self, domain, content):
        headers = {'X-API-Key': self.PDNS_API_KEY, 'Content-Type': 'application/json'}
        data = {"rrsets": [{"name": self.name + '.', "type": self.type, "ttl": self.ttl, "changetype": "REPLACE", "records": [{"content": content, "disabled": self.status,}]}]}
        try:
            utils.fetch_json(urljoin(
                self.PDNS_STATS_URL, self.API_EXTENDED_URL +
                '/servers/localhost/zones/{0}'.format(domain)),
                             headers=headers,
                             timeout=int(Setting().get('pdns_api_timeout')),
                             method='PATCH',
                             verify=Setting().get('verify_ssl_connections'),
                             data=data)
            # current_app.logger.debug("dyndns data: {0}".format(data))
            return {'status': 'ok', 'msg': 'Record was updated successfully'}
        except Exception as e:
            current_app.logger.error(f"Cannot add record {self.name}/{self.type}/{self.data} to zone {domain}. DETAIL: {e}")
            return {'status': 'error', 'msg': 'There was something wrong'}

    def update_db_serial(self, domain):
        headers = {'X-API-Key': self.PDNS_API_KEY}
        jdata = utils.fetch_json(urljoin(
            self.PDNS_STATS_URL, self.API_EXTENDED_URL +
            '/servers/localhost/zones/{0}'.format(domain)),
                                 headers=headers,
                                 timeout=int(Setting().get('pdns_api_timeout')),
                                 method='GET',
                                 verify=Setting().get('verify_ssl_connections'))
        serial = jdata['serial']
        domain_obj = Domain.query.filter(Domain.name == domain).first()
        if domain_obj:
            domain_obj.serial = serial
            db.session.commit()
            return {'status': True, 'msg': f'Synced local serial for zone name {domain}'}
        else:
            return {'status': False, 'msg': f'Could not find zone name {domain} in local db'}

    def create(self, domain_name, rrset):
        rrsets_in_zone = self.get_rrsets(domain_name)
        check = list(filter(lambda r: r['name'] == rrset['rrsets'][0]['name'], rrsets_in_zone))
        if check:
            existing_record = check[0]
            if existing_record['type'] == rrset['rrsets'][0]['type']:
                record_name_display = rrset['rrsets'][0]['name'].rstrip('.')
                return {
                    'status': 'error',
                    'msg': f'''
                    <div class="alert-content">
                        <p class="mb-2"><strong>Record Already Exists!</strong></p>
                        <p class="mb-2">A load balancer record for <code class="bg-light px-2 py-1 rounded">{record_name_display}</code> already exists in this zone.</p>
                        <p class="mb-0">Please use the edit function to modify the existing record or choose a different name.</p>
                    </div>
                    '''
                }
        headers = {'X-API-Key': self.PDNS_API_KEY, 'Content-Type': 'application/json'}
        try:
            rrset['rrsets'][0]['changetype'] = 'REPLACE'
            jdata = utils.fetch_json(urljoin(
                self.PDNS_STATS_URL, self.API_EXTENDED_URL +
                '/servers/localhost/zones/{0}'.format(domain_name)),
                                     headers=headers,
                                     timeout=int(Setting().get('pdns_api_timeout')),
                                     method='PATCH',
                                     verify=Setting().get('verify_ssl_connections'),
                                     data=rrset)
            # current_app.logger.debug(jdata)
            return {'status': 'ok', 'msg': 'Record was created successfully'}
        except Exception as e:
            current_app.logger.error(f"Cannot create record in zone {domain_name}. Error: {e}")
            # current_app.logger.debug(f"Submitted record rrset: \n{utils.pretty_json(rrset)}")
            return {'status': 'error', 'msg': 'There was something wrong'}