"""ChurchHub MVP: single-church event and administration app."""
import os
import sqlite3
import secrets
from datetime import date
from functools import wraps
from pathlib import Path
from flask import Flask, abort, flash, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import Markup

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('CHURCH_SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('CHURCH_HTTPS') == '1',
    MAX_CONTENT_LENGTH=1024 * 1024,
)
DB_PATH = Path(os.environ.get('CHURCH_DB_PATH', str(BASE / 'church.db')))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','organizer')));
CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, phone TEXT, email TEXT, department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, title TEXT NOT NULL, event_date TEXT NOT NULL, location TEXT, description TEXT, budget_cents INTEGER NOT NULL DEFAULT 0 CHECK(budget_cents>=0));
CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'To do' CHECK(status IN ('To do','In progress','Done')));
CREATE TABLE IF NOT EXISTS expenses (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, category TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>=0), notes TEXT);
CREATE TABLE IF NOT EXISTS attendance (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE, member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE, UNIQUE(event_id,member_id));
"""


def db():
    if 'db' not in g:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop('db', None)
    if conn is not None: conn.close()

@app.before_request
def init_and_protect():
    db().executescript(SCHEMA)
    # On first cloud deployment, create an administrator from PRIVATE host settings.
    # Never put CHURCH_ADMIN_PASSWORD in this source code or GitHub.
    initial_username = os.environ.get('CHURCH_ADMIN_USERNAME', '').strip()
    initial_password = os.environ.get('CHURCH_ADMIN_PASSWORD', '')
    if initial_username and initial_password and len(initial_password) >= 12:
        existing = db().execute('SELECT 1 FROM users LIMIT 1').fetchone()
        if not existing:
            try:
                with db():
                    db().execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',
                                 (initial_username, generate_password_hash(initial_password), 'admin'))
            except sqlite3.IntegrityError:
                pass
    if request.method == 'POST' and request.form.get('_csrf') != session.get('_csrf'):
        abort(400, 'Invalid form token. Refresh the page and retry.')
    if '_csrf' not in session: session['_csrf'] = secrets.token_hex(24)

@app.template_filter('rand')
def rand(cents):
    return f'R {cents / 100:,.2f}'

BASE_HTML = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · ChurchHub</title>
<style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#192438;background:#f5f7fb}*{box-sizing:border-box}body{margin:0}.top{background:#18264a;color:white;padding:17px 5%;display:flex;align-items:center;gap:22px;flex-wrap:wrap}.brand{font-weight:800;font-size:21px}.top a{color:#e2eaff;text-decoration:none;font-size:14px}.top form{margin-left:auto}.top button{background:transparent;border:1px solid #8ea0c5;color:white;padding:7px 12px;border-radius:7px;cursor:pointer}.wrap{max-width:1080px;margin:32px auto;padding:0 20px}h1{font-size:29px;margin:0 0 20px}h2{font-size:19px;margin:0 0 16px}.card{background:white;border:1px solid #e1e6ee;border-radius:12px;padding:22px;margin-bottom:20px;box-shadow:0 2px 7px #172a4810}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:18px}.stat{font-size:29px;font-weight:750;color:#374db6}.muted{color:#67758b;font-size:14px}label{display:block;font-weight:600;font-size:14px;margin:14px 0 5px}input,select,textarea{width:100%;padding:11px;border:1px solid #bcc6d5;border-radius:7px;font:inherit}textarea{min-height:75px}button,.btn{display:inline-block;background:#394cbb;color:white;border:0;padding:11px 17px;border-radius:7px;cursor:pointer;font:inherit;text-decoration:none;margin-top:14px}.btn.secondary{background:#e9edff;color:#25358f}.alert{padding:12px 15px;border-radius:8px;background:#e9f3e9;margin:10px 0}.danger{background:#fff0eb}.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;border-bottom:1px solid #e8ecf1;font-size:14px}th{color:#526179}a{color:#3046aa}.inline{display:inline}.inline button{font-size:12px;padding:7px;margin:0}.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.mini{max-width:550px}.pill{background:#edf0fa;padding:5px 9px;border-radius:30px;font-size:12px}hr{border:0;border-top:1px solid #e7e9f1;margin:20px 0}.btn-delete{background:#b4232c}.task-list{display:grid;gap:12px}.task-item{border:1px solid #e1e6ee;border-radius:10px;padding:14px;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:14px;align-items:center}.task-title{font-weight:700;overflow-wrap:anywhere}.task-meta{color:#67758b;font-size:13px;margin-top:5px}.task-controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.task-controls form{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.task-controls select{min-width:130px}.task-controls button{margin-top:0}.task-controls .btn-delete{white-space:nowrap}@media(max-width:650px){.top{padding:14px 16px;gap:10px}.top .brand{width:100%}.top a{font-size:14px;padding:7px 6px}.top form{margin-left:0}.wrap{margin:20px auto;padding:0 12px}h1{font-size:24px}.card{padding:16px;margin-bottom:14px}.grid{grid-template-columns:minmax(0,1fr);gap:8px}.stat{font-size:25px}.task-item{grid-template-columns:minmax(0,1fr)}.task-controls{width:100%}.task-controls form{width:100%}.task-controls select{flex:1;min-width:0}.task-controls button{flex-shrink:0}button,.btn{min-height:42px}input,select,textarea{font-size:16px}table{min-width:550px}}</style></head><body>
<header class="top"><span class="brand">✦ ChurchHub</span>{% if session.get('uid') %}<a href="{{ url_for('home') }}">Dashboard</a><a href="{{ url_for('departments') }}">Departments</a><a href="{{ url_for('members') }}">Members</a><a href="{{ url_for('events') }}">Events</a><form action="{{ url_for('logout') }}" method="post"><input type="hidden" name="_csrf" value="{{ session['_csrf'] }}"><button>Log out</button></form>{% endif %}</header>
<main class="wrap"><h1>{{ title }}</h1>{% with messages=get_flashed_messages() %}{% if messages %}{% for msg in messages %}<div class="alert">{{msg}}</div>{% endfor %}{% endif %}{% endwith %}{{ content|safe }}</main></body></html>'''

def page(title, html, **context):
    content = render_template_string(html, **context)
    return render_template_string(BASE_HTML, title=title, content=Markup(content))

def login_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not session.get('uid'): return redirect(url_for('login'))
        return fn(*a, **kw)
    return inner

def value(field, max_len=160, required=True):
    text = request.form.get(field, '').strip()
    if (required and not text) or len(text) > max_len: abort(400, f'Invalid {field}')
    return text

def amount(field):
    from decimal import Decimal, InvalidOperation
    try:
        v = Decimal(value(field, 16))
        if not v.is_finite() or v < 0 or v.as_tuple().exponent < -2 or v > 100000000: raise ValueError()
        return int(v * 100)
    except (InvalidOperation, ValueError): abort(400, 'Enter a nonnegative amount with up to two decimal places.')

def integer(field, nullable=False):
    raw = request.form.get(field, '')
    if nullable and raw == '': return None
    try:
        n = int(raw)
        if n < 1: raise ValueError()
        return n
    except ValueError: abort(400, 'Invalid selection')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = value('username', 80)
        password = request.form.get('password', '')
        person = db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if person and check_password_hash(person['password_hash'], password):
            session.clear(); session['uid'] = person['id']; session['role'] = person['role']; session['_csrf'] = secrets.token_hex(24)
            return redirect(url_for('home'))
        flash('Incorrect username or password.')
    return page('Sign in', '''<div class="card mini"><form method="post"><input type="hidden" name="_csrf" value="{{ session['_csrf'] }}"><label>Username</label><input name="username" required maxlength="80"><label>Password</label><input name="password" type="password" required><button>Sign in</button></form><p class="muted">An administrator account is created during setup.</p></div>''')

@app.post('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    counts = {table: db().execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ('members','departments','events','tasks')}
    upcoming = db().execute('SELECT * FROM events WHERE event_date >= ? ORDER BY event_date LIMIT 8', (date.today().isoformat(),)).fetchall()
    return page('Church dashboard', '''<div class="grid">{% for name,count in counts.items() %}<div class="card"><div class="stat">{{count}}</div><div class="muted">{{name|capitalize}}</div></div>{% endfor %}</div><div class="card"><h2>Upcoming events</h2>{% if upcoming %}<div class="scroll"><table><tr><th>Date</th><th>Event</th><th>Location</th></tr>{% for x in upcoming %}<tr><td>{{x.event_date}}</td><td><a href="{{url_for('event_detail', event_id=x.id)}}">{{x.title}}</a></td><td>{{x.location or '—'}}</td></tr>{% endfor %}</table></div>{% else %}<p class="muted">No upcoming events. Create your first event.</p>{% endif %}<a class="btn" href="{{ url_for('events') }}">Manage events</a></div>''', counts=counts, upcoming=upcoming)

@app.route('/departments', methods=['GET','POST'])
@login_required
def departments():
    if request.method == 'POST':
        try:
            with db(): db().execute('INSERT INTO departments(name) VALUES (?)', (value('name',100),))
            flash('Department added.')
        except sqlite3.IntegrityError: flash('That department already exists.')
        return redirect(url_for('departments'))
    items = db().execute('SELECT d.*,COUNT(m.id) AS members FROM departments d LEFT JOIN members m ON m.department_id=d.id GROUP BY d.id ORDER BY d.name').fetchall()
    return page('Departments', '''<div class="card mini"><h2>Add department</h2><form method="post"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><label>Name</label><input name="name" maxlength="100" required placeholder="e.g. Music"><button>Add department</button></form></div><div class="card"><h2>All departments</h2><table><tr><th>Department</th><th>Members</th></tr>{% for d in items %}<tr><td>{{d.name}}</td><td>{{d.members}}</td></tr>{% endfor %}</table></div>''', items=items)

@app.route('/members', methods=['GET','POST'])
@login_required
def members():
    if request.method == 'POST':
        try:
            with db(): db().execute('INSERT INTO members(full_name,phone,email,department_id) VALUES (?,?,?,?)',(value('full_name'),value('phone',30,False),value('email',150,False),integer('department_id',True)))
            flash('Member added.')
        except sqlite3.IntegrityError: abort(400,'Invalid department')
        return redirect(url_for('members'))
    items = db().execute('SELECT m.*,d.name department FROM members m LEFT JOIN departments d ON d.id=m.department_id ORDER BY m.full_name').fetchall()
    deps = db().execute('SELECT * FROM departments ORDER BY name').fetchall()
    return page('Members', '''<div class="card mini"><h2>Add member</h2><form method="post"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><label>Full name</label><input name="full_name" required maxlength="160"><label>Phone (optional)</label><input name="phone" maxlength="30"><label>Email (optional)</label><input name="email" type="email" maxlength="150"><label>Department</label><select name="department_id"><option value="">Unassigned</option>{% for d in deps %}<option value="{{d.id}}">{{d.name}}</option>{% endfor %}</select><button>Add member</button></form></div><div class="card scroll"><h2>Member directory</h2><table><tr><th>Name</th><th>Phone</th><th>Email</th><th>Department</th></tr>{% for m in items %}<tr><td>{{m.full_name}}</td><td>{{m.phone}}</td><td>{{m.email}}</td><td>{{m.department or '—'}}</td></tr>{% endfor %}</table></div>''', items=items, deps=deps)

@app.route('/events', methods=['GET','POST'])
@login_required
def events():
    if request.method == 'POST':
        event_date = value('event_date',10)
        try: date.fromisoformat(event_date)
        except ValueError: abort(400,'Invalid event date')
        with db(): db().execute('INSERT INTO events(title,event_date,location,description,budget_cents) VALUES (?,?,?,?,?)',(value('title'),event_date,value('location',160,False),value('description',2000,False),amount('budget')))
        flash('Event created.')
        return redirect(url_for('events'))
    items = db().execute('SELECT e.*,COALESCE((SELECT SUM(amount_cents) FROM expenses x WHERE x.event_id=e.id),0) spent FROM events e ORDER BY e.event_date DESC').fetchall()
    return page('Events', '''<div class="card mini"><h2>Create event</h2><form method="post"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><label>Event name</label><input name="title" required maxlength="160"><label>Date</label><input type="date" name="event_date" required><label>Location</label><input name="location" maxlength="160"><label>Description</label><textarea name="description" maxlength="2000"></textarea><label>Budget (R)</label><input type="number" name="budget" value="0" min="0" step="0.01" required><button>Create event</button></form></div><div class="card scroll"><h2>Events</h2><table><tr><th>Event</th><th>Date</th><th>Budget</th><th>Spent</th></tr>{% for e in items %}<tr><td><a href="{{url_for('event_detail',event_id=e.id)}}">{{e.title}}</a></td><td>{{e.event_date}}</td><td>{{e.budget_cents|rand}}</td><td>{{e.spent|rand}}</td></tr>{% endfor %}</table></div>''',items=items)

@app.route('/events/<int:event_id>')
@login_required
def event_detail(event_id):
    event = db().execute('SELECT * FROM events WHERE id=?',(event_id,)).fetchone()
    if event is None: abort(404)
    deps = db().execute('SELECT * FROM departments ORDER BY name').fetchall()
    members = db().execute('SELECT * FROM members ORDER BY full_name').fetchall()
    tasks = db().execute('SELECT t.*,d.name department FROM tasks t LEFT JOIN departments d ON d.id=t.department_id WHERE event_id=? ORDER BY t.id DESC',(event_id,)).fetchall()
    expenses = db().execute('SELECT * FROM expenses WHERE event_id=? ORDER BY id DESC',(event_id,)).fetchall()
    attendees = db().execute('SELECT m.full_name FROM attendance a JOIN members m ON m.id=a.member_id WHERE a.event_id=? ORDER BY m.full_name',(event_id,)).fetchall()
    spent = sum(x['amount_cents'] for x in expenses)
    return page(event['title'], '''<p class="muted">{{event.event_date}} · {{event.location or 'Location not specified'}}</p><p>{{event.description}}</p><div class="grid"><div class="card"><div class="muted">Planned budget</div><div class="stat">{{event.budget_cents|rand}}</div></div><div class="card"><div class="muted">Total spent</div><div class="stat">{{spent|rand}}</div></div><div class="card"><div class="muted">Remaining budget</div><div class="stat">{{(event.budget_cents-spent)|rand}}</div></div></div>
<div class="grid"><div class="card"><h2>Assign task</h2><form method="post" action="{{url_for('add_task',event_id=event.id)}}"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><label>Task</label><input name="title" required maxlength="160" placeholder="Prepare one pot of food"><label>Department</label><select name="department_id"><option value="">Unassigned</option>{% for d in deps %}<option value="{{d.id}}">{{d.name}}</option>{% endfor %}</select><button>Add task</button></form></div>
<div class="card"><h2>Add expense</h2><form method="post" action="{{url_for('add_expense',event_id=event.id)}}"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><label>Category</label><input name="category" required maxlength="100" placeholder="Food"><label>Amount (R)</label><input name="amount" type="number" min="0" step="0.01" required><label>Notes</label><input name="notes" maxlength="250"><button>Add expense</button></form></div></div>
<div class="card"><h2>Task progress</h2><div class="task-list">{% for t in tasks %}<div class="task-item"><div><div class="task-title">{{t.title}}</div><div class="task-meta">{{t.department or 'Unassigned'}}</div></div><div class="task-controls"><form method="post" action="{{url_for('update_task',task_id=t.id)}}"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><select name="status" aria-label="Status for {{t.title}}">{% for s in ['To do','In progress','Done'] %}<option value="{{s}}" {% if t.status==s %}selected{% endif %}>{{s}}</option>{% endfor %}</select><button>Save</button></form><form method="post" action="{{url_for('delete_task',task_id=t.id)}}" onsubmit="return confirm('Delete this task? This cannot be undone.');"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><button type="submit" class="btn-delete" aria-label="Delete {{t.title}}">Delete</button></form></div></div>{% else %}<p class="muted">No tasks yet. Add your first task above.</p>{% endfor %}</div></div>
<div class="card"><h2>Expenses</h2><table><tr><th>Category</th><th>Notes</th><th>Amount</th></tr>{% for x in expenses %}<tr><td>{{x.category}}</td><td>{{x.notes}}</td><td>{{x.amount_cents|rand}}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>Attendance ({{attendees|length}})</h2><form method="post" action="{{url_for('mark_attendance',event_id=event.id)}}"><input type="hidden" name="_csrf" value="{{session['_csrf']}}"><label>Mark member attending</label><select name="member_id" required><option value="">Select member</option>{% for m in members %}<option value="{{m.id}}">{{m.full_name}}</option>{% endfor %}</select><button>Mark attending</button></form><p>{% for a in attendees %}<span class="pill">{{a.full_name}}</span> {% endfor %}</p></div>''',event=event,deps=deps,members=members,tasks=tasks,expenses=expenses,attendees=attendees,spent=spent)

@app.post('/events/<int:event_id>/tasks')
@login_required
def add_task(event_id):
    try:
        with db(): db().execute('INSERT INTO tasks(event_id,department_id,title) VALUES (?,?,?)',(event_id,integer('department_id',True),value('title')))
    except sqlite3.IntegrityError: abort(400,'Invalid event or department')
    flash('Task assigned.')
    return redirect(url_for('event_detail',event_id=event_id))

@app.post('/tasks/<int:task_id>/status')
@login_required
def update_task(task_id):
    status=value('status',20)
    if status not in ('To do','In progress','Done'): abort(400)
    task=db().execute('SELECT event_id FROM tasks WHERE id=?',(task_id,)).fetchone()
    if not task: abort(404)
    with db(): db().execute('UPDATE tasks SET status=? WHERE id=?',(status,task_id))
    return redirect(url_for('event_detail',event_id=task['event_id']))

@app.post('/tasks/<int:task_id>/delete')
@login_required
def delete_task(task_id):
    task = db().execute('SELECT event_id FROM tasks WHERE id=?', (task_id,)).fetchone()
    if task is None:
        abort(404)
    # Only an administrator can permanently remove tasks.
    if session.get('role') != 'admin':
        abort(403)
    with db():
        db().execute('DELETE FROM tasks WHERE id=?', (task_id,))
    flash('Task deleted.')
    return redirect(url_for('event_detail', event_id=task['event_id']))

@app.post('/events/<int:event_id>/expenses')
@login_required
def add_expense(event_id):
    try:
        with db(): db().execute('INSERT INTO expenses(event_id,category,amount_cents,notes) VALUES (?,?,?,?)',(event_id,value('category',100),amount('amount'),value('notes',250,False)))
    except sqlite3.IntegrityError: abort(400,'Invalid event')
    flash('Expense saved.')
    return redirect(url_for('event_detail',event_id=event_id))

@app.post('/events/<int:event_id>/attendance')
@login_required
def mark_attendance(event_id):
    try:
        with db(): db().execute('INSERT OR IGNORE INTO attendance(event_id,member_id) VALUES (?,?)',(event_id,integer('member_id')))
    except sqlite3.IntegrityError: abort(400,'Invalid member or event')
    flash('Attendance updated.')
    return redirect(url_for('event_detail',event_id=event_id))

@app.cli.command('create-admin')
def create_admin():
    import getpass
    username = input('New admin username: ').strip()
    if not username or len(username)>80: raise SystemExit('Username must be 1-80 characters.')
    password = getpass.getpass('New admin password (12+ characters): ')
    if len(password)<12: raise SystemExit('Password too short.')
    with app.app_context():
        db().executescript(SCHEMA)
        try:
            with db(): db().execute('INSERT INTO users(username,password_hash,role) VALUES (?,?,?)',(username,generate_password_hash(password),'admin'))
        except sqlite3.IntegrityError: raise SystemExit('Username already exists.')
    print('Administrator created. You can sign in.')

if __name__ == '__main__':
    app.run(host=os.environ.get('CHURCH_HOST', '127.0.0.1'), port=int(os.environ.get('PORT', 5000)), debug=False)
