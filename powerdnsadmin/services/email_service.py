from flask import current_app
from flask_mail import Mail, Message
from ..models.setting import Setting
import datetime

mail = Mail()

def init_mail(app):
    from ..models.setting import Setting
    """Initialize Flask-Mail with the application"""
    with app.app_context():
        app.config['MAIL_SERVER'] = Setting().get('smtp_server')
        app.config['MAIL_PORT'] = Setting().get('smtp_port')
        app.config['MAIL_USERNAME'] = Setting().get('smtp_username')
        app.config['MAIL_PASSWORD'] = Setting().get('smtp_password')
        app.config['MAIL_USE_TLS'] = Setting().get('mail_use_tls')
        app.config['MAIL_USE_SSL'] = Setting().get('mail_use_ssl')
        app.config['MAIL_DEFAULT_SENDER'] = Setting().get('mail_default_sender')
        app.config['MAIL_DEBUG'] = Setting().get('mail_debug')
    mail.init_app(app)


def send_email(subject, body, recipients):
    """Generic email sending function using Flask-Mail."""
    print(f"GENERIC_EMAIL_PRINT: send_email called. Subject: '{subject}', Recipients: {recipients}")

    if not recipients:
        current_app.logger.warning("No recipients provided for email.")
        print("GENERIC_EMAIL_PRINT: No recipients provided. Exiting.")
        return False
    try:
        if isinstance(recipients, str):
            recipients = [email.strip() for email in recipients.split(',')]
        elif not isinstance(recipients, list):
            current_app.logger.error("Recipients must be a string or a list.")
            return False

        msg = Message(subject=subject, recipients=recipients, body=body)
        print("GENERIC_EMAIL_PRINT: Message object created. Attempting mail.send(msg)...")
        mail.send(msg)
        current_app.logger.info(f"Email sent to {recipients} with subject: {subject}")
        print(f"GENERIC_EMAIL_PRINT: mail.send(msg) successful for {subject} to {recipients}.")
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        print(f"GENERIC_EMAIL_PRINT: EXCEPTION in mail.send(msg) for {subject} to {recipients}: {e}")
        return False


def send_port_status_change_alert(lua_record_name, backend_ip, port_number, new_status):
    """Sends an email when a backend port status changes for a LUA record."""
    print(f"EMAIL_SENDER_PRINT: send_port_status_change_alert called for {lua_record_name} ({backend_ip}:{port_number}) - New status: {new_status}")
    try:
        notification_emails_str = Setting().get('notification_emails')
        print(f"EMAIL_SENDER_PRINT: Notification emails string: '{notification_emails_str}'")

        if not notification_emails_str:
            current_app.logger.warning("NOTIFICATION_EMAILS not configured, cannot send port status alert.")
            print("EMAIL_SENDER_PRINT: No notification_emails configured. Exiting.")
            return False

        notify_up_setting = Setting().get('notify_port_up')
        notify_down_setting = Setting().get('notify_port_down')
        print(f"EMAIL_SENDER_PRINT: notify_port_up setting: {notify_up_setting}, notify_port_down setting: {notify_down_setting}")

        # ตรวจสอบว่าควรส่ง notification สำหรับสถานะนี้หรือไม่
        if new_status == 'UP' and not Setting().get('notify_port_up'):
            current_app.logger.info(f"Port UP notification disabled for {lua_record_name} - {backend_ip}:{port_number}")
            print(f"EMAIL_SENDER_PRINT: Port UP notification disabled for {lua_record_name}. Exiting.")
            return True

        if new_status == 'DOWN' and not Setting().get('notify_port_down'):
            current_app.logger.info(f"Port DOWN notification disabled for {lua_record_name} - {backend_ip}:{port_number}")
            print(f"EMAIL_SENDER_PRINT: Port DOWN notification disabled for {lua_record_name}. Exiting.")
            return True

        subject = f"LB Alert: {lua_record_name} - Backend {backend_ip}:{port_number} is now {new_status}"
        body = f"""
        Load Balancer Backend Status Change Notification

        LUA Record: {lua_record_name}
        Backend Server IP: {backend_ip}
        Port: {port_number}
        New Status: {new_status}
        Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

        This is an automated notification from PowerDNS Admin.
        """
        recipients = [email.strip() for email in notification_emails_str.split(',')]
        print(f"EMAIL_SENDER_PRINT: Prepared to send email. Subject: '{subject}', Recipients: {recipients}")
        
        email_sent_successfully = send_email(subject, body, recipients)
        
        if email_sent_successfully:
            print(f"EMAIL_SENDER_PRINT: send_email reported success for {lua_record_name}.")
        else:
            print(f"EMAIL_SENDER_PRINT: send_email reported FAILURE for {lua_record_name}.")
        return email_sent_successfully

    except Exception as e:
        current_app.logger.error(f"Failed to prepare or send port status change alert: {str(e)}")
        print(f"EMAIL_SENDER_PRINT: EXCEPTION in send_port_status_change_alert: {e}")
        return False

def send_test_email(recipient_email):
    """Send a test email to verify email configuration"""
    try:
        subject = "Test Email from PowerDNS Admin"
        body = f"""
        This is a test email from PowerDNS Admin.
        
        If you received this email, your email notification settings are working correctly.
        
        Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        msg = Message(subject=subject, recipients=[recipient_email], body=body)
        mail.send(msg)
        return True, "Test email sent successfully"
        
    except Exception as e:
        error_msg = str(e)
        current_app.logger.error(f"Failed to send test email: {error_msg}")
        return False, f"Failed to send test email: {error_msg}" 