import requests
import json
import datetime
import os

# --- CONFIGURATION ---
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = "public"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "index.html")

# Vendors to track (Case insensitive matching)
# key = display name, value = list of search terms
VENDORS = {
    'Microsoft': ['microsoft'],
    'Cisco': ['cisco'],
    'Citrix': ['citrix'],
    'Palo Alto': ['palo alto'],
    'Check Point': ['checkpoint', 'check point']
}

# EOL Products to track (slugs from endoflife.date)
EOL_SLUGS = {
    'windows': 'Windows Desktop',
    'windows-server': 'Windows Server',
    'exchange-server': 'Exchange Server',
    'office': 'Office / M365 Apps',
    'sql-server': 'SQL Server'
}

def fetch_cisa_data():
    try:
        r = requests.get(CISA_URL)
        r.raise_for_status()
        data = r.json()
        
        relevant_vulns = []
        for v in data.get('vulnerabilities', []):
            vendor_field = v.get('vendorProject', '').lower()
            product_field = v.get('product', '').lower()
            
            # Determine which vendor bucket this belongs to
            assigned_vendor = None
            for category, keywords in VENDORS.items():
                if any(k in vendor_field for k in keywords):
                    assigned_vendor = category
                    break
            
            if assigned_vendor:
                # Add extra metadata for the UI
                v['ui_category'] = assigned_vendor
                v['link'] = f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"
                relevant_vulns.append(v)
                
        # Sort by date added (newest first)
        return sorted(relevant_vulns, key=lambda x: x['dateAdded'], reverse=True)[:60]
    except Exception as e:
        print(f"Error fetching CISA: {e}")
        return []

def fetch_eol_data():
    items = []
    today = datetime.date.today()
    
    for slug, name in EOL_SLUGS.items():
        try:
            r = requests.get(f"https://endoflife.date/api/{slug}.json")
            if r.status_code != 200: continue
            
            # Get only the last 5 versions to keep list clean
            versions = r.json()[:5] 
            
            for v in versions:
                eol = v.get('eol')
                if not eol or eol == False: continue
                
                # Parse date
                try:
                    eol_dt = datetime.datetime.strptime(eol, "%Y-%m-%d").date()
                except:
                    continue
                    
                days_left = (eol_dt - today).days
                status = "ok"
                if days_left < 0: status = "expired"
                elif days_left < 365: status = "warning"
                
                # Only show if expired recently (last 2 years) or future
                if days_left > -730: 
                    items.append({
                        'product': f"{name} {v.get('cycle')}",
                        'eol': eol,
                        'status': status,
                        'sort_date': eol_dt
                    })
        except:
            continue
            
    return sorted(items, key=lambda x: x['sort_date'])

def generate_html(vulns, eol):
    # Professional Slate/Blue Theme
    css = """
        :root { --bg: #f8f9fa; --sidebar: #1e293b; --card: #ffffff; --text: #334155; --accent: #0f172a; --highlight: #2563eb; --critical: #ef4444; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--text); display: flex; min-height: 100vh; }
        
        /* Sidebar */
        .sidebar { width: 280px; background: var(--sidebar); color: white; padding: 2rem; position: fixed; height: 100%; overflow-y: auto; }
        .sidebar h1 { font-size: 1.2rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 2rem; border-bottom: 1px solid #334155; padding-bottom: 1rem; }
        .filter-btn { display: block; width: 100%; padding: 12px; margin-bottom: 8px; background: #334155; border: none; color: white; text-align: left; cursor: pointer; border-radius: 6px; transition: 0.2s; }
        .filter-btn:hover, .filter-btn.active { background: var(--highlight); }
        .eol-section { margin-top: 3rem; }
        .eol-item { font-size: 0.85rem; padding: 8px 0; border-bottom: 1px solid #334155; }
        .eol-date { display: block; font-size: 0.75rem; opacity: 0.7; margin-top: 2px; }
        .st-warning { color: #f59e0b; } .st-expired { text-decoration: line-through; opacity: 0.5; } .st-ok { color: #10b981; }

        /* Main Content */
        .main { margin-left: 280px; padding: 2rem 3rem; width: 100%; }
        .header { margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }
        .last-updated { font-size: 0.9rem; color: #64748b; }
        
        /* Cards */
        .grid { display: grid; gap: 1.5rem; }
        .card { background: var(--card); padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid var(--highlight); transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .card.vendor-Microsoft { border-left-color: #0078d4; }
        .card.vendor-Cisco { border-left-color: #1ba0d7; }
        .card.vendor-Citrix { border-left-color: #d13438; }
        .card.vendor-Palo { border-left-color: #f97316; }
        
        .card-header { display: flex; justify-content: space-between; margin-bottom: 1rem; }
        .tag { background: #f1f5f9; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .cve-link { color: var(--highlight); text-decoration: none; font-weight: 700; font-size: 1.1rem; }
        .cve-link:hover { text-decoration: underline; }
        .desc { font-size: 0.95rem; line-height: 1.6; margin-bottom: 1rem; color: #475569; }
        .action { background: #eff6ff; padding: 12px; border-radius: 6px; font-size: 0.9rem; border: 1px solid #dbeafe; }
        
        /* Mobile */
        @media (max-width: 900px) { body { display: block; } .sidebar { position: relative; width: auto; height: auto; } .main { margin: 0; padding: 1rem; } }
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
                const cards = document.querySelectorAll('.card');
                const buttons = document.querySelectorAll('.filter-btn');
                
                // Update buttons
                buttons.forEach(b => b.classList.remove('active'));
                document.getElementById('btn-'+vendor).classList.add('active');
                
                // Filter cards
                cards.forEach(card => {{
                    if (vendor === 'All' || card.dataset.vendor === vendor) {{
                        card.style.display = 'block';
                    }} else {{
                        card.style.display = 'none';
                    }}
                }});
            }}
        </script>
    </head>
    <body>
        <div class="sidebar">
            <h1>Threat Intel</h1>
            
            <p style="color:#94a3b8; font-size:0.8rem; margin-bottom:10px;">VULNERABILITY FILTER</p>
            <button id="btn-All" class="filter-btn active" onclick="filter('All')">All Vendors</button>
            <button id="btn-Microsoft" class="filter-btn" onclick="filter('Microsoft')">Microsoft</button>
            <button id="btn-Cisco" class="filter-btn" onclick="filter('Cisco')">Cisco</button>
            <button id="btn-Citrix" class="filter-btn" onclick="filter('Citrix')">Citrix</button>
            <button id="btn-Palo Alto" class="filter-btn" onclick="filter('Palo Alto')">Palo Alto</button>
            
            <div class="eol-section">
                <p style="color:#94a3b8; font-size:0.8rem; margin-bottom:10px;">LIFECYCLE (MICROSOFT)</p>
                {''.join([f'<div class="eol-item st-{i["status"]}"><strong>{i["product"]}</strong><span class="eol-date">{i["eol"]}</span></div>' for i in eol])}
            </div>
        </div>
        
        <div class="main">
            <div class="header">
                <h2>Active Exploitations (CISA KEV)</h2>
                <div class="last-updated">Updated: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
            </div>
            
            <div class="grid">
    """
    
    for v in vulns:
        # Vendor class for styling
        v_cls = v['ui_category'].split()[0] if v['ui_category'] else 'Other'
        
        html += f"""
        <div class="card vendor-{v_cls}" data-vendor="{v['ui_category']}">
            <div class="card-header">
                <span class="tag">{v['ui_category']}</span>
                <span class="tag" style="background: white; border: 1px solid #ddd;">{v['dateAdded']}</span>
            </div>
            <a href="{v['link']}" target="_blank" class="cve-link">{v['vulnerabilityName']} ({v['cveID']}) ↗</a>
            <p class="desc">{v['shortDescription']}</p>
            <div class="action">
                <strong>REQUIRED ACTION:</strong> {v['requiredAction']}
            </div>
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
    print(f"Found {len(vulns)} vulnerabilities.")
    
    print("Fetching EOL...")
    eol = fetch_eol_data()
    
    print("Generating Dashboard...")
    with open(OUTPUT_FILE, 'w') as f:
        f.write(generate_html(vulns, eol))
    print("Done.")
