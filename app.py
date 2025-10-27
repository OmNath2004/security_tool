# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
import sqlite3
import io
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production

# Database setup
def init_db():
    conn = sqlite3.connect('requirements.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS requirements
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  functional_req TEXT NOT NULL,
                  security_req TEXT NOT NULL,
                  priority TEXT NOT NULL,
                  category TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# Enhanced keyword-based security suggestion with more templates
def suggest_security_req(functional_req):
    req_lower = functional_req.lower()
    suggestions = {
        'auth': ["user", "login", "authenticate", "register", "session"],
        'payment': ["payment", "transaction", "financial", "billing", "card"],
        'data': ["data", "store", "database", "save", "retrieve"],
        'api': ["api", "endpoint", "rest", "web service"],
        'network': ["network", "connect", "upload", "download"],
        'access': ["access", "permission", "role", "admin"],
        'compliance': ["gdpr", "hipaa", "pci", "regulation"]
    }
    
    for key, keywords in suggestions.items():
        if any(word in req_lower for word in keywords):
            templates = {
                'auth': "Implement secure authentication (OAuth 2.0/JWT, MFA). Use secure session management and protect against CSRF/XSS.",
                'payment': "Integrate PCI DSS compliant gateways. Encrypt PII with AES-256 at rest and TLS 1.3 in transit. Add fraud detection.",
                'data': "Enforce data minimization and encryption. Implement RBAC and audit trails for compliance (e.g., GDPR).",
                'api': "Secure with API keys, rate limiting, and OWASP top 10 mitigations (e.g., input validation, CORS).",
                'network': "Use HTTPS everywhere, certificate pinning, and secure protocols to prevent MITM attacks.",
                'access': "Apply principle of least privilege with RBAC/ABAC. Regular access reviews and logging.",
                'compliance': "Map to standards like NIST/ISO 27001. Conduct privacy impact assessments and data protection by design."
            }
            return templates.get(key, "Perform threat modeling per SQUARE: Identify assets, threats, and controls for CIA triad.")
    
    return "Baseline security: Input validation, error handling without leaks, and regular vulnerability scans."

# Get stats for dashboard
def get_stats():
    conn = sqlite3.connect('requirements.db')
    c = conn.cursor()
    c.execute('SELECT priority, COUNT(*) FROM requirements GROUP BY priority')
    stats = dict(c.fetchall())
    conn.close()
    return stats

# Routes
@app.route('/')
def index():
    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    
    conn = sqlite3.connect('requirements.db')
    c = conn.cursor()
    query = 'SELECT * FROM requirements WHERE 1=1'
    params = []
    
    if search:
        query += ' AND (functional_req LIKE ? OR security_req LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    if category_filter:
        query += ' AND category = ?'
        params.append(category_filter)
    
    query += ' ORDER BY created_at DESC'
    c.execute(query, params)
    requirements = c.fetchall()
    
    categories = ['Auth', 'Payment', 'Data', 'API', 'Network', 'Access', 'Compliance', 'Other']
    stats = get_stats()
    conn.close()
    return render_template('index.html', requirements=requirements, search=search, category_filter=category_filter, categories=categories, stats=stats)

@app.route('/suggest', methods=['POST'])
def suggest():
    functional_req = request.json.get('functional_req', '')
    security_req = suggest_security_req(functional_req)
    return jsonify({'security_req': security_req})

@app.route('/add', methods=['GET', 'POST'])
def add_req():
    if request.method == 'POST':
        functional_req = request.form['functional_req']
        if not functional_req:
            flash('Functional requirement cannot be empty!')
            return redirect(url_for('add_req'))
        
        security_req = request.form['security_req'] or suggest_security_req(functional_req)
        priority = request.form['priority']
        category = request.form['category']
        
        conn = sqlite3.connect('requirements.db')
        c = conn.cursor()
        c.execute('INSERT INTO requirements (functional_req, security_req, priority, category) VALUES (?, ?, ?, ?)',
                  (functional_req, security_req, priority, category))
        conn.commit()
        conn.close()
        
        flash('Requirement added successfully!')
        return redirect(url_for('index'))
    
    return render_template('add.html')

@app.route('/edit/<int:req_id>', methods=['GET', 'POST'])
def edit_req(req_id):
    conn = sqlite3.connect('requirements.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        functional_req = request.form['functional_req']
        security_req = request.form['security_req']
        priority = request.form['priority']
        category = request.form['category']
        
        c.execute('UPDATE requirements SET functional_req=?, security_req=?, priority=?, category=? WHERE id=?',
                  (functional_req, security_req, priority, category, req_id))
        conn.commit()
        conn.close()
        flash('Requirement updated successfully!')
        return redirect(url_for('index'))
    
    c.execute('SELECT * FROM requirements WHERE id=?', (req_id,))
    req = c.fetchone()
    conn.close()
    
    if not req:
        flash('Requirement not found!')
        return redirect(url_for('index'))
    
    categories = ['Auth', 'Payment', 'Data', 'API', 'Network', 'Access', 'Compliance', 'Other']
    return render_template('edit.html', req=req, categories=categories)

@app.route('/delete/<int:req_id>')
def delete_req(req_id):
    conn = sqlite3.connect('requirements.db')
    c = conn.cursor()
    c.execute('DELETE FROM requirements WHERE id=?', (req_id,))
    conn.commit()
    conn.close()
    flash('Requirement deleted successfully!')
    return redirect(url_for('index'))

@app.route('/export')
def export_report():
    conn = sqlite3.connect('requirements.db')
    c = conn.cursor()
    c.execute('SELECT * FROM requirements ORDER BY priority DESC, created_at DESC')
    requirements = c.fetchall()
    conn.close()
    
    # Enhanced HTML report with categories and stats
    stats = get_stats()
    report_html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Security Assurance Case Report</title>
    <style>table {{border-collapse: collapse; width: 100%;}} th, td {{border: 1px solid #ddd; padding: 8px;}} th {{background-color: #f2f2f2;}}</style>
    </head>
    <body>
        <h1>Security Assurance Case Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h2>Statistics</h2>
        <ul>
            <li>High: {stats.get('High', 0)}</li>
            <li>Medium: {stats.get('Medium', 0)}</li>
            <li>Low: {stats.get('Low', 0)}</li>
            <li>Total: {sum(stats.values())}</li>
        </ul>
        <h2>Prioritized Security Requirements</h2>
        <table>
            <tr><th>ID</th><th>Category</th><th>Functional Requirement</th><th>Security Requirement</th><th>Priority</th><th>Created</th></tr>
    """
    
    for req in requirements:
        report_html += f"""
            <tr>
                <td>{req[0]}</td>
                <td>{req[4] or 'Other'}</td>
                <td>{req[1]}</td>
                <td>{req[2]}</td>
                <td>{req[3]}</td>
                <td>{req[5]}</td>
            </tr>
        """
    
    report_html += """
        </table>
        <p>This assurance case aligns functional requirements with security controls per SQUARE process (Unit III) and builds evidence for security claims (Unit II).</p>
    </body>
    </html>
    """
    
    output = io.BytesIO()
    output.write(report_html.encode('utf-8'))
    output.seek(0)
    
    return send_file(output, mimetype='text/html', as_attachment=True, download_name='security_assurance_report.html')

if __name__ == '__main__':
    app.run(debug=True)