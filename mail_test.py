import smtplib, ssl, sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from email.header import Header

if len(sys.argv) > 1:
	input_text = "".join(sys.argv[1:])
else:
	input_text = ""

SMTP_HOST = "mail.secureskies.lan"
SMTP_PORT = 587
USERNAME = "lmokciski"
PASSWORD = "GoldenGateBridge2@"

FROM_ADDR = "lmokciski@secureskies.lan"
FROM_NAME = "Lisa Mokciski"
TO = ["dmorris@secureskies.lan"]
SUBJECT = "python script test"

msg=MIMEMultipart("alternative")
msg["From"] = formataddr((str(Header(FROM_NAME, "utf-8")), FROM_ADDR))
msg["To"] = ", ".join(TO)
msg["Subject"] = SUBJECT

text = f"Hello test email {input_text}"

msg.attach(MIMEText(text, "plain"))

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
	server.ehlo()
	server.starttls(context=context)
	server.ehlo()
	server.login(USERNAME, PASSWORD)
	server.sendmail(FROM_ADDR, TO, msg.as_string())

print("Mail sent successfully")
