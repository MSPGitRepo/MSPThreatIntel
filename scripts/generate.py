import requests
import json
import datetime
import os
import xml.etree.ElementTree as ET
import re

# --- CONFIGURATION ---
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = "public"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "index.html")

# 1. VENDORS TO TRACK
# Keys = Button Label, Values = Search Keywords (lowercase)
VENDORS = {
    'Microsoft': ['microsoft'],
    'Cisco': ['cisco'],
    'Citrix': ['citrix'],
    'Palo Alto': ['palo alto'],
    'Check Point': ['checkpoint', 'check point'],
    'Fortinet': ['fortinet', 'fortigate'],
    'Aruba': ['aruba', 'hpe networking']  # <--- Added Aruba
}

# 2. LIFECYCLE TRACKING
EOL_SLUGS = {
    'Windows Desktop': 'windows',
    'Windows Server': 'windows-server',
    'Exchange Server': 'exchange-server',
    'SQL Server': 'sql-server',
    'Office / M365': 'office',
    'Azure AD Connect': 'azure-aad-connect',
    'SharePoint Server': 'sharepoint'
}

# 3. NEWS SOURCES
NEWS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"}
]
NEWS_TRIGGERS = ['cve-', 'zero-day', 'exploit', 'rce', 'critical', 'patch', 'vulnerability', 'backdoor']

# 4. STATUS SOURCES
AZURE_STATUS_RSS = "https://azure.status.microsoft/en-gb/status/feed/"
WINDOWS_HEALTH_RSS = "https://learn.microsoft.com/api/search/rss?search=%22known%20issue%22&locale=en-us&scopename=Windows%20Release%20Health"

def fetch_cisa_data():
    try:
        r = requests.get(CISA_URL)
        r.raise_for_status()
        data = r.json()
        relevant_vulns = []
        
        for v in data.get('vulnerabilities', []):
            vendor_field = v.get('vendorProject', '').lower()
            
            # --- LOGIC UPDATE: Default to "Other" ---
            assigned_vendor = "Other"
            
            for category, keywords in VENDORS.items():
                if any(k in vendor_field for k in keywords):
                    assigned_vendor = category
                    break
            
            v['ui_category'] = assigned_vendor
            v['link'] = f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"
            
            # KQL only for Microsoft
            if assigned_vendor == 'Microsoft':
                v['kql'] = f"DeviceTvmSoftwareVulnerabilities | where CveId == '{v.get('cveID')}' | summarize count() by DeviceName"
            else:
                v['kql'] = None
            
            relevant_vulns.append(v)
            
        return sorted(relevant_vulns, key=lambda x: x['dateAdded'], reverse=True)[:100] # Increased limit to see "Other" items
    except Exception as e:
        print(f"Error fetching CISA: {e}")
        return []

def fetch_eol_data():
    items = []
    today = datetime.date.today()
    for friendly_name, slug in EOL_SLUGS.items():
        try:
            r = requests.get(f"https://endoflife.date/api/{slug}.json")
            if r.status_code != 200: continue
            versions = r.json()[:5]
            for v in versions:
                eol = v.get('eol')
                if not eol or eol == False: continue
                try:
                    eol_dt = datetime.datetime.strptime(eol, "%Y-%m-%d").date()
                except: continue
                days_left = (eol_dt - today).days
                if days_left > -730: 
                    status = "ok"
                    if days_left < 0: status = "expired"
                    elif days_left < 365: status = "warning"
                    items.append({'product': f"{friendly_name} {v.get('cycle')}", 'eol': eol, 'status': status, 'sort_date': eol_dt})
        except: continue
    return sorted(items, key=lambda x: x['sort_date'])

def fetch_security_news():
    news_items = []
    for source in NEWS_FEEDS:
        try:
            r = requests.get(source['url'], timeout=5)
            root = ET.fromstring(r.content)
            for item in root.findall('./channel/item')[:10]:
                title = item.find('title').text
                link = item.find('link').text
                desc = item.find('description').text if item.find('description') is not None else ""
                combined_text = (title + " " + desc).lower()
                if any(trigger in combined_text for trigger in NEWS_TRIGGERS):
                    news_items.append({"source": source['name'], "title": title, "link": link, "date": item.find('pubDate').text[:16] if item.find('pubDate') is not None else ""})
        except Exception as e: continue
    return news_items[:15]

def fetch_status_updates():
    status_items = []
    try:
        r = requests.get(AZURE_STATUS_RSS, timeout=5)
        root = ET.fromstring(r.content)
        for item in root.findall('./channel/item')[:5]:
            status_items.append({
                "type": "Azure Outage",
                "title": item.find('title').text,
                "desc": item.find('description').text,
                "date": item.find('pubDate').text[:16],
                "link": item.find('link').text,
                "severity": "critical" 
            })
    except Exception as e: print(f"Azure RSS Error: {e}")

    try:
        r = requests.get(WINDOWS_HEALTH_RSS, timeout=5)
        root = ET.fromstring(r.content)
        for item in root.findall('./channel/item')[:10]:
            title = item.find('title').text
            if "known issue" in title.lower() or "status" in title.lower():
                clean_desc = item.find('description').text
                if "See all messages" in clean_desc:
                    clean_desc = clean_desc.split("See all messages")[0]
                status_items.append({
                    "type": "Windows Issue",
                    "title": title.replace(" known issues and notifications", ""), 
                    "desc": clean_desc + "...",
                    "date": item.find('pubDate').text[:16],
                    "link": item.find('link').text,
                    "severity": "warning"
                })
    except Exception as e: print(f"Windows RSS Error: {e}")
            
    return status_items

def generate_html(vulns, eol, news, status):
    # --- UI GENERATION (Split to avoid Syntax Errors) ---
    
    # 1. Vendor Buttons
    vendor_buttons_html = f'<button id="btn-All" class="filter-btn active" onclick="filter(\'All\')">All Vendors</button>'
    for k in VENDORS.keys():
        vendor_buttons_html += f'<button id="btn-{k}" class="filter-btn" onclick="filter(\'{k}\')">{k}</button>'
    # Add "Other" Button
    vendor_buttons_html += '<button id="btn-Other" class="filter-btn" onclick="filter(\'Other\')">Other / Misc</button>'

    # 2. EOL List
    eol_list_html = ""
    for i in eol:
        eol_list_html += f'''
        <div class="eol-item st-{i["status"]}">
            <span class="eol-prod">{i["product"]}</span>
            <span class="eol-date">{i["eol"]}</span>
        </div>'''

    # 3. Vulnerability Cards
    vuln_cards_html = ""
    for v in vulns:
        v_cls = v['ui_category'].split()[0] if v['ui_category'] else 'Other'
        kql = ""
        if v.get('kql'):
            kql = f'<div class="kql-box"><div class="kql-code">KQL: {v["kql"]}</div><button class="copy-btn" onclick="copyKql(\'{v["cveID"]}\')">Copy</button></div>'
        
        vuln_cards_html += f"""
        <div class="card vendor-{v_cls}" data-vendor="{v['ui_category']}">
            <span class="tag">{v['ui_category']}</span><span class="tag" style="float:right">{v['dateAdded']}</span>
            <a href="{v['link']}" target="_blank" class="cve-title">{v['vulnerabilityName']} ({v['cveID']}) ↗</a>
            <p style="font-size:0.9rem; color:#475569;">{v['shortDescription']}</p>
            <div style="font-size:0.8rem; background:#eff6ff; padding:8px; border-radius:4px; color:#1e40af;"><strong>ACTION:</strong> {v['requiredAction']}</div>
            {kql}
        </div>"""

    # 4. Status Items
    status_html = ""
    if not status: status_html = "<p>No active major outages or known issues found.</p>"
    for s in status:
        status_html += f"""
        <div class="list-item status-{s['severity']}">
            <span class="meta" style="color:{'#ef4444' if s['severity']=='critical' else '#f59e0b'}">{s['type']} • {s['date']}</span>
            <a href="{s['link']}" target="_blank" class="item-link">{s['title']} ↗</a>
            <div class="item-desc">{s['desc']}</div>
        </div>"""

    # 5. News Items
    news_html = ""
    for n in news:
        news_html += f"""
        <div class="list-item">
            <span class="meta">{n['source']} • {n['date']}</span>
            <a href="{n['link']}" target="_blank" class="item-link">{n['title']} ↗</a>
        </div>"""

    # --- CSS Styles ---
    css = """
        :root { --bg: #f8fafc; --sidebar: #0f172a; --card: #ffffff; --text: #334155; --accent: #2563eb; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); display: flex; min-height: 100vh; }
        .sidebar { width: 340px; background: var(--sidebar); color: #e2e8f0; padding: 2rem; position: fixed; height: 100%; overflow-y: auto; flex-shrink: 0; box-sizing: border-box; }
        .sidebar h1 { font-size: 1.2rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 2rem; border-bottom: 1px solid #334155; padding-bottom: 1rem; color: white; }
        .eol-item { font-size: 0.85rem; padding: 10px 0; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
        .eol-prod { font-weight: 500; color: #cbd5e1; padding-right: 10px; }
        .eol-date { font-family: monospace; opacity: 0.9; font-size: 0.85rem; white-space: nowrap; color: #94a3b8; }
        .st-warning .eol-date { color: #f59e0b; font-weight:bold; } 
        .st-expired { text-decoration: line-through; opacity: 0.5; }
        .main { margin-left: 340px; padding: 2rem 3rem; width: 100%; box-sizing: border-box; }
        .section-label { font-size: 0.75rem; color: #94a3b8; margin: 25px 0 10px 0; font-weight: bold; letter-spacing: 0.5px; }
        .filter-btn { display: block; width: 100%; padding: 10px; margin-bottom: 5px; background: #1e293b; border: 1px solid #334155; color: #cbd5e1; text-align: left; cursor: pointer; border-radius: 6px; transition: 0.2s; }
        .filter-btn:hover, .filter-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
        .tab-nav { display: flex; gap: 20px; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; overflow-x: auto; }
        .tab-btn { padding: 10px 20px; cursor: pointer; font-weight: 600; color: #64748b; border-bottom: 3px solid transparent; white-space: nowrap; }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .grid { display: grid; gap: 1.5rem; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); }
        .card { background: var(--card); padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-left: 5px solid #ccc; }
        
        /* Vendor Colors */
        .card.vendor-Microsoft { border-left-color: #0078d4; }
        .card.vendor-Cisco { border-left-color: #1ba0d7; }
        .card.vendor-Citrix { border-left-color: #d13438; }
        .card.vendor-Aruba { border-left-color: #ff8300; } /* Orange */
        .card.vendor-Other { border-left-color: #64748b; } /* Grey */
        
        .list-item { background: white; padding: 20px; margin-bottom: 15px; border-radius: 8px; border-left: 5px solid #334155; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .status-critical { border-left-color: #ef4444; } 
        .status-warning { border-left-color: #f59e0b; }
        .meta { font-size: 0.75rem; font-weight: bold; margin-bottom: 8px; display: block; letter-spacing: 0.5px; }
        .item-link { text-decoration: none; color: #1e293b; font-weight: 700; font-size: 1.1rem; display: block; margin-bottom: 8px; }
        .item-link:hover { color: var(--accent); text-decoration: underline; }
        .item-desc { font-size: 0.95rem; color: #475569; line-height: 1.6; }
        .tag { background: #f1f5f9; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: #475569; }
        .cve-title { display: block; color: var(--accent); font-weight: 700; font-size: 1.05rem; margin: 10px 0; text-decoration: none; }
        .kql-box { margin-top: 15px; background: #f8fafc; padding: 10px; border: 1px solid #e2e8f0; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .kql-code { font-family: monospace; font-size: 0.75rem; color: #334155; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; max-width: 80%; }
        .copy-btn { background: white; border: 1px solid #cbd5e1; cursor: pointer; padding: 4px 8px; font-size: 0.7rem; border-radius: 4px; }
        @media (max-width: 1000px) { 
            body { display: block; } 
            .sidebar { width: auto; position: relative; height: auto; padding: 1rem; } 
            .main { margin: 0; padding: 1rem; } 
        }
    """

    # --- FINAL HTML ASSEMBLY ---
    # We use .format() or manual concatenation to avoid f-string complexity issues
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MSP Threat Intel</title>
        <style>{css}</style>
        <script>
            function filter(vendor) {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                document.getElementById('btn-'+vendor).classList.add('active');
                document.querySelectorAll('.card').forEach(card => {{
                    card.style.display = (vendor === 'All' || card.dataset.vendor === vendor) ? 'block' : 'none';
                }});
            }}
            function switchTab(tabId) {{
                document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.getElementById(tabId).classList.add('active');
                document.getElementById('tab-btn-'+tabId).classList.add('active');
            }}
            function copyKql(cve) {{
                const query = "DeviceTvmSoftwareVulnerabilities | where CveId == '" + cve + "' | summarize count() by DeviceName";
                navigator.clipboard.writeText(query);
                alert("KQL Copied");
            }}
        </script>
    </head>
    <body>
        <div class="sidebar">
            <h1>MSP Threat Intel</h1>
            <div class="section-label">VULNERABILITY FILTER</div>
            {vendor_buttons_html}
            <div class="section-label">LIFECYCLE TRACKER</div>
            {eol_list_html}
        </div>
        
        <div class="main">
            <div class="tab-nav">
                <div id="tab-btn-vulns" class="tab-btn active" onclick="switchTab('vulns')">Active Exploits</div>
                <div id="tab-btn-status" class="tab-btn" onclick="switchTab('status')">Outages & Known Issues</div>
                <div id="tab-btn-news" class="tab-btn" onclick="switchTab('news')">Intel Feed</div>
            </div>
            
            <div id="vulns" class="tab-content active">
                <div class="grid">
                    {vuln_cards_html}
                </div>
            </div>
            
            <div id="status" class="tab-content">
                <h3>Live Service Status (Public Feeds)</h3>
                {status_html}
            </div>

            <div id="news" class="tab-content">
                <h3>Curated Security News</h3>
                {news_html}
            </div>
        </div>
    </body>
    </html>
    """
    return html

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    print("Fetching Data...")
    vulns = fetch_cisa_data()
    eol = fetch_eol_data()
    news = fetch_security_news()
    status = fetch_status_updates()
    
    with open(OUTPUT_FILE, 'w') as f:
        f.write(generate_html(vulns, eol, news, status))
    print("Dashboard Updated.")
