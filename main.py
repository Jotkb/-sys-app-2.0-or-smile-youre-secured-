import os
from modules.port_scanner import scan_ports
from modules.brute_force import ssh_brute_force
from modules.service_detect import grab_banner
from modules.web_scanner import check_sql_injection
from modules.gh_domain_scanner import scan_gh_domains
from modules.fintech_security import check_api_security
from modules.compliance import check_ssl_expiry, check_http_security_headers
from modules.ai_engine import generate_summary, get_update_rules
from utils.logger import log_to_file, generate_html_report
from utils.emailer import send_email_report
from utils.alerting import send_sms_hubtel, send_whatsapp_twilio

import dotenv
dotenv.load_dotenv()

print("\n=== SYS APP — Smile You're Secured ===")

host = input("Enter target IP or domain: ").strip()
ports = scan_ports(host)
print(f"Open ports: {ports}")

report_lines = [f"Scan results for {host}:"]
log_to_file("output.txt", report_lines[0])

for port in ports:
    banner = grab_banner(host, port)
    banner_text = f"Port {port}: {banner}" if banner else f"Port {port}: No banner"
    print(banner_text)
    report_lines.append(banner_text)
    log_to_file("output.txt", banner_text)

if 22 in ports:
    username = input("Enter SSH username to brute-force: ").strip()
    with open("wordlists/passwords.txt") as f:
        passwords = f.readlines()
    found_pwd = ssh_brute_force(host, username, passwords)
    if found_pwd:
        result = f"SSH Password found: {found_pwd}"
        report_lines.append(result)
        log_to_file("output.txt", result)

if 80 in ports or 443 in ports:
    url = f"http://{host}"
    if check_sql_injection(url):
        msg = "Possible SQL Injection vulnerability detected."
        print(msg)
        report_lines.append(msg)
        log_to_file("output.txt", msg)

    api_issues = check_api_security(url)
    for issue in api_issues:
        print(issue)
        report_lines.append(issue)
        log_to_file("output.txt", issue)

    missing_headers = check_http_security_headers(url)
    if missing_headers:
        header_msg = "Missing HTTP security headers: " + ", ".join(missing_headers)
        print(header_msg)
        report_lines.append(header_msg)
        log_to_file("output.txt", header_msg)

    ssl_days = check_ssl_expiry(host)
    if ssl_days < 0:
        ssl_msg = "Unable to verify SSL certificate expiry."
    else:
        ssl_msg = f"SSL certificate expires in {ssl_days} days."
    print(ssl_msg)
    report_lines.append(ssl_msg)
    log_to_file("output.txt", ssl_msg)

gh_domains = scan_gh_domains([host])
if gh_domains:
    for domain, ips in gh_domains.items():
        gh_msg = f"Ghana domain {domain} resolves to IPs: {ips}"
        print(gh_msg)
        report_lines.append(gh_msg)
        log_to_file("output.txt", gh_msg)

html_report_path = "reports/report.html"
os.makedirs("reports", exist_ok=True)
generate_html_report("\n".join(report_lines), html_report_path)

summary = generate_summary("\n".join(report_lines))
print("\n=== AI-Generated Executive Summary ===")
print(summary)
report_lines.append("\n=== AI Summary ===\n" + summary)

update_rules = get_update_rules()
print("\n=== Latest Pentesting Rules from AI ===")
print(update_rules)

send = input("Would you like to email the report? (y/n): ").strip().lower()
if send == 'y':
    recipient = input("Enter recipient email: ").strip()
    send_email_report(recipient, "Sys App Pentest Report", html_report_path)

alert_send = input("Send SMS/WhatsApp alert? (y/n): ").strip().lower()
if alert_send == 'y':
    phone = input("Enter phone number (+233...): ").strip()
    message = f"Sys App Scan Summary:\n{summary}"
    hubtel_api_key = os.getenv('HUBTEL_API_KEY')
    hubtel_api_secret = os.getenv('HUBTEL_API_SECRET')
    twilio_sid = os.getenv('TWILIO_SID')
    twilio_token = os.getenv('TWILIO_AUTH_TOKEN')
    twilio_whatsapp_from = os.getenv('TWILIO_WHATSAPP_FROM')

    if hubtel_api_key and hubtel_api_secret:
        if send_sms_hubtel(phone, message, hubtel_api_key, hubtel_api_secret):
            print("[+] SMS alert sent via Hubtel")
        else:
            print("[-] Failed to send SMS alert via Hubtel")

    if twilio_sid and twilio_token and twilio_whatsapp_from:
        try:
            sid = send_whatsapp_twilio(phone, message, twilio_sid, twilio_token, twilio_whatsapp_from)
            print(f"[+] WhatsApp alert sent via Twilio (SID: {sid})")
        except Exception as e:
            print(f"[-] Failed to send WhatsApp alert: {e}")

print("\nScan complete. Results saved to output.txt and report.html")
