"""Reset and verification messages through certificate-verified SMTP."""
from email.message import EmailMessage
import smtplib
import ssl
from urllib.parse import urlsplit


def configured(config):
    origin = urlsplit(config.get('APP_URL', ''))
    valid_origin = origin.scheme == 'https' or (origin.scheme == 'http' and origin.hostname in ('localhost', '127.0.0.1'))
    return bool(valid_origin and origin.netloc and origin.path in ('', '/') and not origin.query
                and not origin.fragment and not origin.username and config.get('SMTP_HOST') and config.get('SMTP_FROM')
                and config.get('SMTP_SECURITY', 'starttls') in ('ssl', 'starttls'))


def send_link(config, address, kind, token):
    if not configured(config):
        raise ValueError('Mail is not configured.')
    message = EmailMessage()
    message['From'] = config['SMTP_FROM']
    message['To'] = address
    message['Subject'] = 'IP Checker: ' + ('reset your password' if kind == 'reset' else 'verify your email')
    url = config['APP_URL'].rstrip('/') + '/login#' + kind + '=' + token
    message.set_content('Use this single-use link to ' + ('reset your IP Checker password' if kind == 'reset' else 'verify your IP Checker email')
                        + ':\n\n' + url + '\n\nThis link expires in ' + ('15 minutes' if kind == 'reset' else 'one hour')
                        + '. If you did not request this, ignore this message. Password resets do not remove two-factor protection.')
    context = ssl.create_default_context()
    port = int(config.get('SMTP_PORT', '587'))
    smtp_class = smtplib.SMTP_SSL if config.get('SMTP_SECURITY') == 'ssl' else smtplib.SMTP
    options = {'timeout': 15}
    if smtp_class is smtplib.SMTP_SSL:
        options['context'] = context
    with smtp_class(config['SMTP_HOST'], port, **options) as smtp:
        if smtp_class is smtplib.SMTP:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        if config.get('SMTP_USER'):
            smtp.login(config['SMTP_USER'], config.get('SMTP_PASSWORD', ''))
        smtp.send_message(message)
