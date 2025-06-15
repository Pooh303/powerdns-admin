import traceback
from flask import current_app
from urllib.parse import urljoin

from ..lib import utils
from .setting import Setting
from .base import db


class Server(db.Model):
    __tablename__ = 'server'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    api_url = db.Column(db.String(256), nullable=False)
    api_key = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256))
    health_records = db.relationship('ServerHealth', backref='server', lazy=True)

    def __init__(self, name, api_url, api_key, description=None):
        self.name = name
        self.api_url = api_url
        self.api_key = api_key
        self.description = description

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'api_url': self.api_url,
            'description': self.description
        }

    def get_config(self):
        """
        Get server config
        """
        headers = {'X-API-Key': self.api_key}

        try:
            jdata = utils.fetch_json(urljoin(
                self.api_url, '/servers/{0}/config'.format(self.id)),
                                     headers=headers,
                                     timeout=int(Setting().get('pdns_api_timeout')),
                                     method='GET',
                                     verify=Setting().get('verify_ssl_connections'))
            return jdata
        except Exception as e:
            current_app.logger.error(
                "Can not get server configuration. DETAIL: {0}".format(e))
            current_app.logger.debug(traceback.format_exc())
            return []

    def get_statistic(self):
        """
        Get server statistics
        """
        headers = {'X-API-Key': self.api_key}

        try:
            jdata = utils.fetch_json(urljoin(
                self.api_url, '/servers/{0}/statistics'.format(self.id)),
                                     headers=headers,
                                     timeout=int(Setting().get('pdns_api_timeout')),
                                     method='GET',
                                     verify=Setting().get('verify_ssl_connections'))
            return jdata
        except Exception as e:
            current_app.logger.error(
                "Can not get server statistics. DETAIL: {0}".format(e))
            current_app.logger.debug(traceback.format_exc())
            return []

    def global_search(self, object_type='all', query=''):
        """
        Search zone/record/comment directly from PDNS API
        """
        headers = {'X-API-Key': self.api_key}

        try:
            jdata = utils.fetch_json(urljoin(
                self.api_url, '/servers/{}/search-data?object_type={}&q={}'.format(
                    self.id, object_type, query)),
                                     headers=headers,
                                     timeout=int(
                                         Setting().get('pdns_api_timeout')),
                                     method='GET',
                                     verify=Setting().get('verify_ssl_connections'))
            return jdata
        except Exception as e:
            current_app.logger.error(
                "Can not make global search. DETAIL: {0}".format(e))
            current_app.logger.debug(traceback.format_exc())
            return []
