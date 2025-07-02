import argparse
import dns.resolver
import dns.query
import dns.zone
import json
import os
import logging
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import pandas as pd
    from jinja2 import Template
except ImportError:
    pd = None
    Template = None

# Constants
LOG_FILE = "dns_suite.log"
HISTORY_FILE = "dns_history.json"
INVENTORY_FILE = None  # set via CLI

# Logger setup
def setup_logger():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

# Extended DNS Record Analysis
def analyze_dns_records(domain):
    records = {}
    types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR']
    for rtype in types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            if rtype in ['A', 'AAAA']:
                records[rtype] = [str(r.address) for r in answers]
            elif rtype == 'MX':
                records[rtype] = [str(r.exchange) for r in answers]
            elif rtype == 'TXT':
                records[rtype] = [r.to_text() for r in answers]
            elif rtype == 'NS':
                records[rtype] = [str(r.target) for r in answers]
            elif rtype == 'CNAME':
                records[rtype] = [str(r.target) for r in answers]
            elif rtype == 'SOA':
                soa = answers[0]
                records[rtype] = [str(soa.mname), str(soa.rname), soa.serial]
            elif rtype == 'SRV':
                records[rtype] = [f"{r.priority} {r.weight} {r.port} {r.target}" for r in answers]
            elif rtype == 'PTR':
                records[rtype] = [r.target.to_text() for r in answers]
            logging.info(f"Fetched {rtype} records for {domain}: {records[rtype]}")
        except Exception as e:
            records[rtype] = f"Error: {e}"
            logging.error(f"Error fetching {rtype} for {domain}: {e}")
    return records

# Zone Transfer Check (unchanged)
def get_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns = [str(s.target) for s in answers]
        logging.info(f"Nameservers for {domain}: {ns}")
        return ns
    except Exception as e:
        logging.error(f"Failed to fetch NS for {domain}: {e}")
        return []

def check_zone_transfer(domain, nameserver):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
        data = zone.to_text().splitlines()
        logging.warning(f"Zone transfer allowed on {nameserver} for {domain}")
        return data
    except Exception:
        logging.info(f"Zone transfer denied on {nameserver} for {domain}")
        return []

# Email Security Analysis (unchanged)
# ... (same as before) ...

# Inventory Management: bulk domains

def load_inventory(path):
    if not os.path.exists(path):
        logging.error(f"Inventory file not found: {path}")
        return []
    with open(path) as f:
        domains = [line.strip() for line in f if line.strip()]
    logging.info(f"Loaded inventory of {len(domains)} domains")
    return domains

# Report Generation

def generate_html_report(results, output):
    if not Template:
        logging.error("jinja2 not installed, cannot generate HTML report")
        return
    template_str = '''<html><head><title>DNS Suite Report</title></head><body><h1>DNS Analysis Report</h1>{% for dom, rec in results.items() %}<h2>{{ dom }}</h2><table border="1"><tr><th>Type</th><th>Value</th></tr>{% for typ, vals in rec.items() %}<tr><td>{{ typ }}</td><td>{{ vals }}</td></tr>{% endfor %}</table>{% endfor %}</body></html>'''
    tpl = Template(template_str)
    html = tpl.render(results=results)
    with open(output, 'w') as f:
        f.write(html)
    logging.info(f"HTML report written to {output}")

def generate_xlsx_report(results, output):
    if not pd:
        logging.error("pandas not installed, cannot generate XLSX report")
        return
    rows = []
    for dom, recs in results.items():
        for typ, vals in recs.items():
            rows.append({'Domain': dom, 'Type': typ, 'Value': ','.join(map(str, vals))})
    df = pd.DataFrame(rows)
    df.to_excel(output, index=False)
    logging.info(f"XLSX report written to {output}")

# Email Alert

def send_email_notification(smtp_server, port, user, password, to_addr, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = user
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(smtp_server, port)
        server.starttls()
        server.login(user, password)
        server.send_message(msg)
        server.quit()
        logging.info(f"Alert email sent to {to_addr}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# CLI Interface

def main():
    setup_logger()
    parser = argparse.ArgumentParser(description='Comprehensive DNS & Email Security Analyzer')
    parser.add_argument('domain', nargs='?', help='Target domain or inventory file')
    parser.add_argument('--inventory', help='Path to file with domains list')
    parser.add_argument('--zone-transfer', action='store_true')
    parser.add_argument('--history', action='store_true')
    parser.add_argument('--email-security', action='store_true')
    parser.add_argument('--report', choices=['html','xlsx'], help='Generate report format')
    parser.add_argument('--report-out', default='report.html', help='Report output path')
    parser.add_argument('--alert-email', action='store_true', help='Send email alert')
    parser.add_argument('--smtp-server')
    parser.add_argument('--smtp-port', type=int, default=587)
    parser.add_argument('--smtp-user')
    parser.add_argument('--smtp-pass')
    parser.add_argument('--to-email')
    args = parser.parse_args()

    # Determine domains set
    domains = []
    if args.inventory:
        domains = load_inventory(args.inventory)
    elif args.domain:
        domains = [args.domain]
    else:
        print("Specify --inventory or a single domain")
        return

    results = {}
    # Parallel execution
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {executor.submit(analyze_dns_records, d): d for d in domains}
        for future in as_completed(future_map):
            dom = future_map[future]
            try:
                recs = future.result()
                results[dom] = recs
            except Exception as e:
                logging.error(f"Error analyzing {dom}: {e}")

    # Reporting
    if args.report == 'html':
        generate_html_report(results, args.report_out)
    elif args.report == 'xlsx':
        generate_xlsx_report(results, args.report_out)

    # Email Alert stub: notify if any zone transfer allowed
    if args.alert_email and args.smtp_server:
        body = []
        for dom, recs in results.items():
            ns = get_nameservers(dom)
            for nsrv in ns:
                z = check_zone_transfer(dom, nsrv)
                if z:
                    body.append(f"[ALERT] {dom} allows zone transfer on {nsrv}")
        if body:
            send_email_notification(
                args.smtp_server, args.smtp_port,
                args.smtp_user, args.smtp_pass,
                args.to_email,
                "DNS Suite Alert", '
'.join(body)
            )

    print(f"Analysis complete for {len(domains)} domain(s). See logs: {LOG_FILE}")

if __name__ == '__main__':
    main()
    main()
