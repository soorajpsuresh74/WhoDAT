import email
from email import policy
import re
import requests
from io import BytesIO

# List of free email domains (example)
FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"}

# Example list of disposable email domains (you can use an API like "disposable-email-domains")
DISPOSABLE_EMAIL_PROVIDERS = {"mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com"}

# Suspicious domains list (Replace this with an actual API call for real-time data)
SUSPICIOUS_DOMAINS = {"scam-example.com", "fraudemail.com", "phishingattack.com"}


def parse_my_mail(file):
    """Parses email file and extracts metadata, content, links, and attachments."""
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
                content = part.get_payload(decode=True).decode(errors='ignore')
                break
    else:
        content = message.get_payload(decode=True).decode(errors='ignore')

    links = extract_links(content)

    attachments = []
    for part in message.iter_attachments():
        filename = part.get_filename()
        if filename:
            attachments.append((filename, part.get_payload(decode=True)))  # Store in memory

    return metadata, content, links, attachments


def extract_links(email_content):
    """Extracts links from email content using regex."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, email_content)


def get_email_domain(email_address):
    """Extracts domain from an email address."""
    return email_address.split("@")[-1] if email_address and "@" in email_address else None


def check_domain_status(domain):
    """Checks if a domain is free, disposable, or suspicious."""
    if domain in FREE_EMAIL_PROVIDERS:
        return "Free Email Provider"
    elif domain in DISPOSABLE_EMAIL_PROVIDERS:
        return "Disposable Email"
    elif domain in SUSPICIOUS_DOMAINS:
        return "Suspicious Domain"
    else:
        return "Unknown / Custom Domain"


class EmailAnalysis:
    def __init__(self, file=None):
        self.file = file
        if self.file:
            self.metadata, self.content, self.links, self.attachments = parse_my_mail(self.file)

            # Extract domain analysis for sender
            sender_domain = get_email_domain(self.metadata.get("From", ""))
            self.domain_status = check_domain_status(sender_domain) if sender_domain else "Unknown"

    def get_analysis(self):
        """Returns a structured email analysis result."""
        return {
            "Metadata": self.metadata,
            "Content": self.content[:500] + "..." if len(self.content) > 500 else self.content,
            "Links": self.links,
            "Attachments": [name for name, _ in self.attachments],
            "Sender Domain Status": self.domain_status
        }
