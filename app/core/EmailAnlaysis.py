import json
import re
import hashlib
import quopri
from email.policy import default
from email.parser import HeaderParser
from email import message_from_file

# Define Regular Expressions
MAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
LINK_REGEX = r"https?://[^\s]+"


def get_headers(mail_data: str, investigation):
    """Get Headers from mail data"""
    headers = HeaderParser().parsestr(mail_data, headersonly=True)
    data = {"Headers": {"Data": {}, "Investigation": {}}}

    for k, v in headers.items():
        data["Headers"]["Data"][k.lower()] = v.replace("\t", "").replace("\n", "")

    if headers.get_all("Received"):
        data["Headers"]["Data"]["received"] = " ".join(headers.get_all("Received")).replace("\t", "").replace("\n", "")

    if investigation:
        if "x-sender-ip" in data["Headers"]["Data"]:
            ip = data["Headers"]["Data"]["x-sender-ip"]
            data["Headers"]["Investigation"]["X-Sender-Ip"] = {
                "Virustotal": f"https://www.virustotal.com/gui/search/{ip}",
                "Abuseipdb": f"https://www.abuseipdb.com/check/{ip}",
            }

        if "reply-to" in data["Headers"]["Data"] and "from" in data["Headers"]["Data"]:
            replyto = re.findall(MAIL_REGEX, data["Headers"]["Data"]["reply-to"])[0]
            mailfrom = re.findall(MAIL_REGEX, data["Headers"]["Data"]["from"])[0]

            conclusion = (
                "Reply Address and From Address is SAME."
                if replyto == mailfrom
                else "Reply Address and From Address is NOT Same. This mail may be SPOOFED."
            )

            data["Headers"]["Investigation"]["Spoof Check"] = {
                "Reply-To": replyto,
                "From": mailfrom,
                "Conclusion": conclusion,
            }

    return data


def get_digests(mail_data: str, filename: str, investigation):
    """Get Hash values of mail"""
    with open(filename, "rb") as f:
        eml_file = f.read()

    data = {
        "Digests": {
            "Data": {
                "File MD5": hashlib.md5(eml_file).hexdigest(),
                "File SHA1": hashlib.sha1(eml_file).hexdigest(),
                "File SHA256": hashlib.sha256(eml_file).hexdigest(),
                "Content MD5": hashlib.md5(mail_data.encode("utf-8")).hexdigest(),
                "Content SHA1": hashlib.sha1(mail_data.encode("utf-8")).hexdigest(),
                "Content SHA256": hashlib.sha256(mail_data.encode("utf-8")).hexdigest(),
            },
            "Investigation": {},
        }
    }

    if investigation:
        for key, value in data["Digests"]["Data"].items():
            data["Digests"]["Investigation"][key] = {"Virustotal": f"https://www.virustotal.com/gui/search/{value}"}

    return data


def get_links(mail_data: str, investigation):
    """Get Links from mail data"""
    if "Content-Transfer-Encoding" in mail_data:
        mail_data = str(quopri.decodestring(mail_data))

    links = list(filter(None, list(dict.fromkeys(re.findall(LINK_REGEX, mail_data)))))

    data = {"Links": {"Data": {str(i + 1): link for i, link in enumerate(links)}, "Investigation": {}}}

    if investigation:
        for i, link in enumerate(links, start=1):
            sanitized_link = link.split("://")[-1] if "://" in link else link
            data["Links"]["Investigation"][str(i)] = {
                "Virustotal": f"https://www.virustotal.com/gui/search/{sanitized_link}",
                "Urlscan": f"https://urlscan.io/search/#{sanitized_link}",
            }

    return data


def get_attachments(filename: str, investigation):
    """Get Attachments from eml file"""
    with open(filename, "r", encoding="utf-8") as f:
        msg = message_from_file(f, policy=default)

    attachments = []
    for attachment in msg.iter_attachments():
        attachments.append(
            {
                "filename": attachment.get_filename(),
                "MD5": hashlib.md5(attachment.get_payload(decode=True)).hexdigest(),
                "SHA1": hashlib.sha1(attachment.get_payload(decode=True)).hexdigest(),
                "SHA256": hashlib.sha256(attachment.get_payload(decode=True)).hexdigest(),
            }
        )

    data = {
        "Attachments": {
            "Data": {str(i + 1): att["filename"] for i, att in enumerate(attachments)},
            "Investigation": {},
        }
    }

    if investigation:
        for att in attachments:
            data["Attachments"]["Investigation"][att["filename"]] = {
                "Virustotal": {
                    "Name Search": f'https://www.virustotal.com/gui/search/{att["filename"]}',
                    "MD5": f'https://www.virustotal.com/gui/search/{att["MD5"]}',
                    "SHA1": f'https://www.virustotal.com/gui/search/{att["SHA1"]}',
                    "SHA256": f'https://www.virustotal.com/gui/search/{att["SHA256"]}',
                }
            }

    return data


def analyze_email_main(filename: str, investigation: bool):
    """Main function to analyze an email"""
    with open(filename, "r", encoding="utf-8") as f:
        mail_data = f.read()

    final_data = {
        "Headers": get_headers(mail_data, investigation),
        "Digests": get_digests(mail_data, filename, investigation),
        "Links": get_links(mail_data, investigation),
        "Attachments": get_attachments(filename, investigation),
    }

    return final_data






