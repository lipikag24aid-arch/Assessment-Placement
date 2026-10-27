# Wellness & Placement Portal

Two projects merged into one Flask + SQLite app.

## Student flow
1. Register (optionally with a **class code**) and log in.
2. **Self Assessment** (13 wellness questions) is the first page.
3. On submit you go straight to **Placement Analysis**: pick C / C++ / Java / Python for the
   coding section, then take the 50-question timed placement quiz.
4. See both reports under **My Results**; PDF download and e-mail for each.

Placement is locked until the Self Assessment has been completed once.

## Faculty flow
1. Log in as faculty and click **Create & get code** on the Classes page.
2. Give students the 6-character code (shown large on the class dashboard).
3. The **class dashboard** shows every student's latest Self Assessment and Placement
   result, stage averages (Aptitude, Coding, Technical Interview, Group Discussion),
   readiness and wellness distributions, and a "suggested follow-up" count.
   It auto-refreshes every 30 s and exports to CSV. Click **Details** for one student.

Faculty only see classes they created. Admin can see all.

## Run
```bash
python -m venv venv
venv\Scripts\activate        # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env       # then edit it (macOS/Linux: cp)
python app.py
```
Open **http://localhost:5000** (the console also prints a `http://<your-ip>:5000` address for students).

## Accounts
| Role | Login |
|------|-------|
| Demo faculty | faculty@wellness.local / faculty123 |
| Admin | admin@wellness.local / admin123 |

**Change these passwords and set `SECRET_KEY` and `FACULTY_SIGNUP_KEY` in `.env` before
real use.** New faculty accounts need the sign-up key (Register -> "Create a faculty account").
The database is created automatically at `instance/portal.db`.

## Privacy
Wellness data is sensitive. Students are told on the join/register pages that faculty can
see their name and results. Faculty see factor scores and the follow-up flag, never the
raw answer to the safety question. Both tools are educational screening / practice aids,
not a diagnosis or a guarantee of placement.

## Notes on the merge
- Wellness and placement results live in separate tables; class links both.
- Old `wellness.db` data from either project is not migrated (fresh `portal.db`).
- The old per-attempt "Compare" page was dropped; History lists all attempts.
- Wellness tips now match the 13 actual factors (the original tip text used factor
  names that never matched).

## HTTP / HTTPS
The app now serves plain **http by default** (`USE_HTTPS=0`), so students scanning the QR code get no certificate warning. Use it only on a trusted classroom network; for a public website enable HTTPS below.
Set `USE_HTTPS=1` to serve HTTPS directly.

**On your own PC / a classroom network (default).** On first start it creates a self-signed
certificate in `certs/` that covers `localhost` and this PC's network addresses. Browsers show
a one-time warning ("Not secure / Your connection is not private"): choose
*Advanced -> Continue*. Students on the same Wi-Fi/LAN open `https://<faculty-PC-ip>:5000`
(printed when the app starts) and accept the same warning once. The traffic is still encrypted.
To avoid the warning, put the PC's hostname in `CERT_HOSTS` in `.env` before first start, or use a real certificate.

**Your own certificate.** Set `PORTAL_SSL_CERT` and `PORTAL_SSL_KEY` in `.env` to your
`fullchain.pem` / `privkey.pem` (for example from Let's Encrypt).

**Public website (recommended for real use).** Run the app behind a server that handles HTTPS
and certificates for you, and set `BEHIND_PROXY=1` in `.env`:
```bash
pip install -r requirements.txt
gunicorn -w 2 -b 127.0.0.1:8000 app:app
```
With Caddy, a two-line `Caddyfile` is enough and gets a free certificate automatically:
```
portal.yourcollege.edu {
    reverse_proxy 127.0.0.1:8000
}
```
With `BEHIND_PROXY=1` the app redirects http -> https and sends the HSTS header.

**Always on:** session cookies are `Secure`, `HttpOnly` and `SameSite=Lax`, with 8-hour
sessions, plus `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy` headers.
Debug mode is off by default (the Flask debugger must never be exposed to a network);
`FLASK_DEBUG=1` restricts the app to this PC. Set `USE_HTTPS=0` only for plain-http testing.

## QR code for each class session
On a class dashboard click **Start session** (30 min / 1 hour / 2 hours). A brand-new QR code is generated every time and the page shows it large for the projector, with a countdown and a live list of students who joined.
* Scanning opens `/j/<token>`; the student logs in (or registers) and is placed in the class automatically.
* Starting a new session, ending it, or letting it expire makes the previous QR stop working.
* The class code still works for joining manually.
* Open the dashboard using the network address (not `localhost`) so the QR points to a URL students' phones can reach.


## Deploy for a public HTTPS mobile link (Render)

1. Upload this project folder to a **private GitHub repository**.
2. In Render, choose **New → Blueprint**, connect the repository, and select this `render.yaml`.
3. Enter a strong private value for `FACULTY_SIGNUP_KEY` when prompted. Render will generate `SECRET_KEY`.
4. Deploy. Render will provide a public URL such as `https://wellness-placement-portal.onrender.com`. The actual URL is assigned by Render after deployment.
5. Open that URL on your phone. Use the same URL to share the portal with students/faculty.

The configuration uses a persistent disk for the SQLite database, so it requires a Render plan that supports persistent disks. Do not use demo credentials or real student wellness data until you change demo passwords and review privacy/security settings. Never upload `.env`, passwords, or student data to GitHub.

The app is configured to run behind Render's HTTPS proxy (`BEHIND_PROXY=1`); do not set `USE_HTTPS=1` on Render.
