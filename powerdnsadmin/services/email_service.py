from flask import current_app
from flask_mail import Mail, Message
from ..models.setting import Setting
import datetime

mail = Mail()

def init_mail(app):
    """Initialize Flask-Mail with the application"""
    app.config['MAIL_SERVER'] = app.config.get('SMTP_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = app.config.get('SMTP_PORT', 587)
    app.config['MAIL_USE_TLS'] = app.config.get('SMTP_USE_TLS', True)
    app.config['MAIL_USERNAME'] = app.config.get('SMTP_USERNAME', '')
    app.config['MAIL_PASSWORD'] = app.config.get('SMTP_PASSWORD', '')
    app.config['MAIL_DEFAULT_SENDER'] = app.config.get('SMTP_DEFAULT_SENDER', '')
    
    mail.init_app(app)


def send_email(subject, body, recipients):
    """Generic email sending function using Flask-Mail."""
    if not recipients:
        current_app.logger.warning("No recipients provided for email.")
        return False
    try:
        if isinstance(recipients, str):
            recipients = [email.strip() for email in recipients.split(',')]
        elif not isinstance(recipients, list):
            current_app.logger.error("Recipients must be a string or a list.")
            return False

        msg = Message(subject=subject, recipients=recipients, body=body)
        mail.send(msg)
        current_app.logger.info(f"Email sent to {recipients} with subject: {subject}")
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        return False


def send_port_status_change_alert(lua_record_name, backend_ip, port_number, new_status):
    """Sends an email when a backend port status changes for a LUA record."""
    try:
        notification_emails_str = Setting().get('notification_emails')
        if not notification_emails_str:
            current_app.logger.warning("NOTIFICATION_EMAILS not configured, cannot send port status alert.")
            return False

        # ตรวจสอบว่าควรส่ง notification สำหรับสถานะนี้หรือไม่
        if new_status == 'UP' and not Setting().get('notify_port_up'):
            current_app.logger.info(f"Port UP notification disabled for {lua_record_name} - {backend_ip}:{port_number}")
            return True # ไม่ใช่ error, แค่ไม่ส่ง
        if new_status == 'DOWN' and not Setting().get('notify_port_down'):
            current_app.logger.info(f"Port DOWN notification disabled for {lua_record_name} - {backend_ip}:{port_number}")
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
        return send_email(subject, body, recipients)

    except Exception as e:
        current_app.logger.error(f"Failed to prepare or send port status change alert: {str(e)}")
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