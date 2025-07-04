import sys
import traceback
import pytimeparse
from ast import literal_eval
from flask import current_app
from .base import db
from powerdnsadmin.lib.settings import AppSettings


class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    value = db.Column(db.Text())

    ZONE_TYPE_FORWARD = 'forward'
    ZONE_TYPE_REVERSE = 'reverse'

    def __init__(self, id=None, name=None, value=None):
        self.id = id
        self.name = name
        self.value = value

    # allow database autoincrement to do its own ID assignments
    def __init__(self, name=None, value=None):
        self.id = None
        self.name = name
        self.value = value

    def set_maintenance(self, mode):
        maintenance = Setting.query.filter(
            Setting.name == 'maintenance').first()

        if maintenance is None:
            value = AppSettings.defaults['maintenance']
            maintenance = Setting(name='maintenance', value=str(value))
            db.session.add(maintenance)

        mode = str(mode)

        try:
            if maintenance.value != mode:
                maintenance.value = mode
                db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error('Cannot set maintenance to {0}. DETAIL: {1}'.format(
                mode, e))
            current_app.logger.debug(traceback.format_exec())
            db.session.rollback()
            return False

    def toggle(self, setting):
        current_setting = Setting.query.filter(Setting.name == setting).first()

        if current_setting is None:
            value = AppSettings.defaults[setting]
            current_setting = Setting(name=setting, value=str(value))
            db.session.add(current_setting)

        try:
            if current_setting.value == "True":
                current_setting.value = "False"
            else:
                current_setting.value = "True"
            db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error('Cannot toggle setting {0}. DETAIL: {1}'.format(
                setting, e))
            current_app.logger.debug(traceback.format_exec())
            db.session.rollback()
            return False

    def set(self, setting, value):
        import json
        current_setting = Setting.query.filter(Setting.name == setting).first()

        if current_setting is None:
            current_setting = Setting(name=setting, value=None)
            db.session.add(current_setting)

        value = AppSettings.convert_type(setting, value)

        converted_value_for_storage = AppSettings.convert_type(setting, value)
        current_app.logger.debug(f"Setting.set - setting: {setting}, original value: {value}, type: {type(value)}")
        current_app.logger.debug(f"Setting.set - converted_value_for_storage: {converted_value_for_storage}, type: {type(converted_value_for_storage)}")

        # if isinstance(value, dict) or isinstance(value, list):
        #     value = json.dumps(value)

        # try:
        #     current_setting.value = value
        #     db.session.commit()
        #     return True

        if isinstance(converted_value_for_storage, dict) or isinstance(converted_value_for_storage, list):
            value_to_store = json.dumps(converted_value_for_storage)
        elif isinstance(converted_value_for_storage, bool):
            value_to_store = "True" if converted_value_for_storage else "False"
        else:
            value_to_store = str(converted_value_for_storage)

        current_app.logger.debug(f"Setting.set - value_to_store in DB: {value_to_store}, type: {type(value_to_store)}")

        try:
            current_setting.value = value_to_store
            db.session.commit()
            return True
        except Exception as e:
            current_app.logger.error('Cannot edit setting {0}. DETAIL: {1}'.format(setting, e))
            current_app.logger.debug(traceback.format_exec())
            db.session.rollback()
            return False

    def get(self, setting):
        if setting in AppSettings.defaults:
            # 1. ดึงจาก Database ก่อนสำหรับ settings ที่ user ควรจะ override ได้
            db_setting_value = None
            # รายชื่อ settings ที่ควรดึงจาก DB ก่อนเสมอ
            user_configurable_settings = [
                'notification_emails', 'notify_port_up', 'notify_port_down',
                'smtp_server', 'smtp_port', 'smtp_username', 'smtp_password',
                'mail_use_tls', 'mail_use_ssl', 'mail_default_sender', 'mail_debug',
                'enable_lua_backend_monitor', 'lua_backend_monitor_interval'
            ]

            if setting in user_configurable_settings:
                db_record = self.query.filter(Setting.name == setting).first()
                if db_record and db_record.value is not None: # ตรวจสอบว่ามีค่าใน DB จริงๆ
                    db_setting_value = db_record.value
                    current_app.logger.debug(f"Setting.get (DB FIRST) - setting: {setting}, value_from_db: {db_setting_value}")
                    return AppSettings.convert_type(setting, db_setting_value)

            # 2. ถ้าไม่เจอใน DB (หรือ setting นั้นไม่ควรดึงจาก DB ก่อน) ให้ลองดึงจาก app.config (ที่มาจาก ENV หรือ default_config.py)
            if setting.upper() in current_app.config:
                config_value = current_app.config[setting.upper()]
                current_app.logger.debug(f"Setting.get (app.config) - setting: {setting}, value_from_config: {config_value}")
                return AppSettings.convert_type(setting, config_value)

            # 3. ถ้าไม่เจอใน app.config ให้ใช้ค่า default จาก AppSettings
            current_app.logger.debug(f"Setting.get (AppSettings.defaults) - setting: {setting}, using AppSettings default")
            return AppSettings.defaults[setting]
        else:
            current_app.logger.error(f'Unknown setting queried: {setting}')
            return None

    def get_group(self, group):
        if not isinstance(group, list):
            group = AppSettings.groups[group]

        result = {}

        for var_name, default_value in AppSettings.defaults.items():
            if var_name in group:
                result[var_name] = self.get(var_name)

        return result

    def get_records_allow_to_edit(self):
        return list(
            set(self.get_supported_record_types(self.ZONE_TYPE_FORWARD) +
                self.get_supported_record_types(self.ZONE_TYPE_REVERSE)))

    def get_supported_record_types(self, zone_type):
        setting_value = []

        if zone_type == self.ZONE_TYPE_FORWARD:
            setting_value = self.get('forward_records_allow_edit')
        elif zone_type == self.ZONE_TYPE_REVERSE:
            setting_value = self.get('reverse_records_allow_edit')

        records = literal_eval(setting_value) if isinstance(setting_value, str) else setting_value
        types = [r for r in records if records[r]]

        # Sort alphabetically if python version is smaller than 3.6
        if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6):
            types.sort()

        return types

    def get_ttl_options(self):
        return [(pytimeparse.parse(ttl), ttl)
                for ttl in self.get('ttl_options').split(',')]
