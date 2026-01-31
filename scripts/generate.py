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

# 1. VENDORS TO TRACK (CISA)
VENDORS = {
    'Microsoft': ['microsoft'],
    'Cisco': ['cisco'],
    'Citrix': ['citrix'],
    'Palo Alto': ['palo alto'],
    'Check Point': ['checkpoint', 'check point'],
    'Fortinet': ['fortinet', 'fortigate']
}

# 2. EXTENDED LIFECYCLE TRACKING
EOL_SLUGS = {
    'Windows Desktop': 'windows',
    'Windows Server': 'windows-server',
    'Exchange Server': 'exchange-server',
    'SQL Server': 'sql-server',
    'Office / M365': 'office',
    'Azure AD Connect': 'azure-aad-connect',
    'SharePoint Server': 'sharepoint'
}

# 3. NEWS SOURCES (RSS)
NEWS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"}
]

NEWS_TRIGGERS = ['cve-', 'zero-day', 'exploit', 'rce', 'critical', 'patch', 'vulnerability', 'backdoor']

def fetch_cisa_data():
    try:
        r = requests.get(CISA_URL)
        r.raise_for_status()
        data = r.json()
        
        relevant_vulns = []
        for v in data.get('vulnerabilities', []):
            vendor_field = v.get('vendorProject', '').lower()
            product_field = v.get('product', '').lower()
            
            assigned_vendor = None
            for category, keywords in VENDORS.items():
                if any(k in vendor_field for k in keywords):
                    assigned_vendor = category
                    break
            
            if assigned_vendor:
                v['ui_category'] = assigned_vendor
                v['link'] = f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"
                if assigned_vendor == 'Microsoft':
                    v['kql'] = f"DeviceTvmSoftwareVulnerabilities | where CveId == '{v.get('cveID')}' | summarize count() by DeviceName"
                else:
                    v['kql'] = None
                relevant_vulns.append(v)
                
        return sorted(relevant_vulns, key=lambda x: x['dateAdded'], reverse=True)[:60]
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
                except:
                    continue
                    
                days_left = (eol_dt - today).days
                
                if days_left > -730: 
                    status = "ok"
                    if days_left < 0: status = "expired"
                    elif days_left < 365: status = "warning"
                    
                    items.append({
                        'product': f"{friendly_name} {v.get('cycle')}",
                        'eol': eol,
                        'status': status,
                        'sort_date': eol_dt
                    })
        except:
            continue
            
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
                    news_items.append({
                        "source": source['name'],
                        "title": title,
                        "link": link,
                        "date": item.find('pubDate').text[:16] if item.find('pubDate') is not None else ""
                    })
        except Exception as e:
            print(f"Skipping {source['name']}: {e}")
            continue
            
    return news_items[:15]

def generate_html(vulns, eol, news):
    # --- PRE-CALCULATE HTML PARTS TO AVOID F-STRING ERRORS ---
    
    # 1. Generate Vendor Buttons HTML
    vendor_buttons_html = f'<button id="btn-All" class="filter-btn active" onclick="filter(\'All\')">All Vendors</button>'
    for k in VENDORS.keys():
        vendor_buttons_html += f'<button id="btn-{k}" class="filter-btn" onclick="filter(\'{k}\')">{k}</button>'

    # 2. Generate EOL List HTML
    eol_list_html = ""
    for i in eol:
        eol_list_html += f'<div class="eol-item st-{i["status"]}"><span>{i["product"]}</span><span class="eol-date">{i["eol"]}</span></div>'

    css = """
        :root { --bg: #f0f2f5; --sidebar: #0f172a; --card: #ffffff; --text: #334155; --accent: #2563eb; --critical: #d13438; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); display: flex; min-height: 100vh; }
        .sidebar { width: 300px; background: var(--sidebar); color: #e2e8f0; padding: 2rem; position: fixed; height: 100%; overflow-y: auto; flex-shrink: 0; }
        .sidebar h1 { font-size: 1.1rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 2rem; border-bottom: 1px solid #334155; padding-bottom: 1rem; color: #fff; }
        .section-label { font-size: 0.75rem; color: #94a3b8; margin: 20px 0 10px 0; font-weight: bold; letter-spacing: 0.5px; }
        .filter-btn { display: block; width: 100%; padding: 10px; margin-bottom: 5px; background: #1e293b; border: 1px solid #334155; color: #cbd5e1; text-align: left; cursor: pointer; border-radius: 6px; transition: 0.2s; }
        .filter-btn:hover, .filter-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
        .eol-item { font-size: 0.85rem; padding: 8px 0; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
        .eol-date { font-family: monospace; opacity: 0.8; font-size: 0.8rem; }
        .st-warning { color: #f59e0b; } .st-expired { text-decoration: line-through; opacity: 0.5; } .st-ok { color: #10b981; }
        .main { margin-left: 300px; padding: 2rem 3rem; width: 100%; }
        .tab-nav { display: flex; gap: 20px; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; }
        .tab-btn { padding: 10px 20px; cursor: pointer; font-weight: 600; color: #64748b; border-bottom: 3px solid transparent; }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .grid { display: grid; gap: 1.5rem; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); }
        .card { background: var(--card); padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border-left: 5px solid #ccc; transition: transform 0.2s; position: relative; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .card.vendor-Microsoft { border-left-color: #0078d4; }
        .card.vendor-Cisco { border-left-color: #1ba0d7; }
        .card.vendor-Citrix { border-left-color: #d13438; }
        .tag { background: #f1f5f9; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: #475569; }
        .cve-title { display: block; color: var(--accent); font-weight: 700; font-size: 1.05rem; margin: 10px 0; text-decoration: none; }
        .cve-title:hover { text-decoration: underline; }
        .kql-box { margin-top: 15px; background: #f8fafc; padding: 10px; border: 1px solid #e2e8f0; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .kql-code { font-family: monospace; font-size: 0.75rem; color: #334155; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; max-width: 80%; }
        .copy-btn { background: white; border: 1px solid #cbd5e1; cursor: pointer; padding: 4px 8px; font-size: 0.7rem; border-radius: 4px; }
        .copy-btn:hover { background: #e2e8f0; }
        .news-item { background: white; padding: 15px; margin-bottom: 10px; border-radius: 6px; border-left: 3px solid #334155; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
        .news-source { font-size: 0.7rem; font-weight: bold; color: #64748b; text-transform: uppercase; }
        .news-link { text-decoration: none; color: #1e293b; font-weight: 600; font-size: 1.1rem; display: block; margin: 5px 0; }
        .news-link:hover { color: var(--accent); }
        @media (max-width: 1000px) { body { display: block; } .sidebar { width: auto; position: relative; height: auto; } .main { margin: 0; padding: 1rem; } }
    """

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
                alert("KQL Copied for " + cve);
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
                <div id="tab-btn-vulns" class="tab-btn active" onclick="switchTab('vulns')">Active Exploits (CISA)</div>
                <div id="tab-btn-news" class="tab-btn" onclick="switchTab('news')">Latest Intel (No Fluff)</div>
            </div>
            
            <div id="vulns" class="tab-content active">
                <div class="grid">
    """
    
    # Generate Vulnerability Cards
    for v in vulns:
        v_cls = v['ui_category'].split()[0] if v['ui_category'] else 'Other'
        kql_block = ""
        if v.get('kql'):
            kql_block = f"""
            <div class="kql-box">
                <div class="kql-code">KQL: {v['kql']}</div>
                <button class="copy-btn" onclick="copyKql('{v['cveID']}')">Copy</button>
            </div>
            """
            
        html += f"""
        <div class="card vendor-{v_cls}" data-vendor="{v['ui_category']}">
            <span class="tag">{v['ui_category']}</span>
            <span class="tag" style="float:right">{v['dateAdded']}</span>
            <a href="{v['link']}" target="_blank" class="cve-title">{v['vulnerabilityName']} ({v['cveID']}) ↗</a>
            <p style="font-size:0.9rem; color:#475569;">{v['shortDescription']}</p>
            <div style="font-size:0.8rem; background:#eff6ff; padding:8px; border-radius:4px; color:#1e40af;">
                <strong>ACTION:</strong> {v['requiredAction']}
            </div>
            {kql_block}
        </div>
        """

    html += """
                </div>
            </div>
            
            <div id="news" class="tab-content">
                <h3 style="color:#0f172a; margin-top:0;">Curated Cyber Security News (Filtered)</h3>
    """
    
    # Generate News Items
    for n in news:
        html += f"""
        <div class="news-item">
            <div class="news-source">{n['source']} • {n['date']}</div>
            <a href="{n['link']}" target="_blank" class="news-link">{n['title']} ↗</a>
        </div>
        """

    html += """
            </div>
        </div>
    </body>
    </html>
    """
    return html

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    
    print("Fetching CISA...")
    vulns = fetch_cisa_data()
    
    print("Fetching EOL...")
    eol = fetch_eol_data()
    
    print("Fetching News...")
    news = fetch_security_news()
    
    with open(OUTPUT_FILE, 'w') as f:
        f.write(generate_html(vulns, eol, news))
    print("Done.")
