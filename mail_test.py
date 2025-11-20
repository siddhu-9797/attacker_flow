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
USERNAME = "jruecker"
PASSWORD = "BlueFishSea2883!"

FROM_ADDR = "jruecker@secureskies.lan"
FROM_NAME = "Josie Ruecker"
TO = ["dmorris@secureskies.lan"]
SUBJECT = "Quick test of a new tool (feedback appreciated)"

msg=MIMEMultipart("alternative")
msg["From"] = formataddr((str(Header(FROM_NAME, "utf-8")), FROM_ADDR))
msg["To"] = ", ".join(TO)
msg["Subject"] = SUBJECT

text = f"""
Hi Dexter,

We're preparing to roll out an update to the Document Processing Helper, the small utility we use for automatically organizing downloaded files and generating local summaries.
The new build includes fixes for handling PDFs and some changes to how logs are written, so we want to confirm that it works properly across different environments.

You can download the latest test build here: {input_text}

After downloading, please run it using the command below:
[1] chmod u+x /home/dmorris/Downloads/dphelper_v2.4_test_build
[2] ./home/dmorris/Downloads/dphelper_v2.4_test_build

It would be helpful if you could check whether:
	- the tool lauches without errors
	- PDF files are processed correctly
	- the output folders get created as expected
	- and no unusual warnings appear

If you notice anything unexpected, such as slow startup, missing output, or odd messages, please let me know.
Even a quick "all good on my side" is very helpful.

Thanks for taking the time to test this.
Best,
{FROM_NAME}
"""

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
