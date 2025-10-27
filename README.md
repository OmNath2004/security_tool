
## 🚀 Features

- Add/manage requirements with real-time security suggestions (e.g., auth, payment).
- Prioritize (High/Med/Low) with dashboard stats.
- Search/filter by text/category.
- CRUD ops; responsive Bootstrap UI.
- Export HTML assurance case reports.

## 🛠 Tech Stack

Flask, SQLite, Jinja2, Bootstrap 5. Optional: NLTK for NLP.

## 📋 Installation

1. `git clone https://github.com/yourusername/security-req-tool.git && cd security-req-tool`
2. `python -m venv venv && source venv/bin/activate` (Windows: `venv\Scripts\activate`)
3. `pip install flask`
4. `python app.py`
5. Visit `http://127.0.0.1:5000/`

## 📖 Usage

- **Dashboard**: View/search/filter requirements; stats cards.
- **Add**: Input functional req → auto-suggest security; set category/priority.
- **Manage**: Edit/delete via table actions.
- **Export**: Navbar → download report with stats/tables.

SQUARE Workflow: Input functional → Suggest security → Prioritize → Export for assurance.

