import smtplib
import sys
import socket

# Import the email modules we'll need
from email.mime.text import MIMEText

sys.path.append('/etc/ffbackup')
import ffbackup_mail

if ffbackup_mail.alert_enabled == False:
    print 'Alert email feature is disabled'
    exit()

# Create a text/plain message
msg = MIMEText(sys.stdin.read())

# me == the sender's email address
# you == the recipient's email address
me = ffbackup_mail.sender_email
you = ffbackup_mail.recipient_email
msg['Subject'] = 'ffbackup client failed (host %s)' % socket.getfqdn()
msg['From'] = me
msg['To'] = you

# Send the message via our own SMTP server, but don't include the
# envelope header.
s = smtplib.SMTP(ffbackup_mail.smtp_host, ffbackup_mail.smtp_port)
s.login(ffbackup_mail.user, ffbackup_mail.password)
s.sendmail(me, [you], msg.as_string())
s.quit()
