import email
from email import policy
import re
from io import BytesIO


def parse_my_mail(file):
    message = email.message_from_binary_file(BytesIO(file.read()), policy=policy.default)

    metadata = {
        "From": message["from"],
        "To": message["to"],
        "Subject": message["subject"],
        "Date": message["date"]
    }

    content = ""
    if message.is_multipart():
        for part in message.iter_parts():
            if part.get_content_type() == "text/plain":
                content = part.get_content()
                break
    else:
        content = message.get_content()

    links = extract_links(content)

    attachments = []
    for part in message.iter_attachments():
        filename = part.get_filename()
        if filename:
            with open(filename, "wb") as f:
                f.write(part.get_payload(decode=True))
            attachments.append(filename)

    return metadata, content, links, attachments


def extract_links(email_content):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    links = re.findall(url_pattern, email_content)
    return links
