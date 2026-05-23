"""Generate a demo test repository with fake secrets for scanning demos."""

import os
import random
import string

from utils.logger import log


def _rand(n=32):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def generate_test_repo(base_path: str = "test_repo") -> str:
    """Create a demo repo with fake secrets and commit history."""
    os.makedirs(base_path, exist_ok=True)

    files = {
        ".env": f"""# Application config
DATABASE_URL=postgres://admin:SuperSecret123!@localhost:5432/myapp
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_{_rand(36)}
OPENAI_API_KEY=sk-{_rand(20)}T3BlbkFJ{_rand(20)}
STRIPE_SECRET_KEY=sk_live_{_rand(24)}
SLACK_BOT_TOKEN=xoxb-1234567890-{_rand(24)}
REDIS_URL=redis://:mypassword@localhost:6379/0
JWT_SECRET=my-super-secret-jwt-key-{_rand(16)}
API_KEY=not-a-real-key
DEBUG=true
""",
        "config/database.yml": f"""production:
  adapter: postgresql
  host: db.internal.company.com
  username: prod_admin
  password: Pr0dP@ssw0rd!2024
  database: main_production
  api_key: {_rand(40)}

staging:
  adapter: postgresql
  host: staging-db.internal
  username: staging_user
  password: staging123
""",
        "src/app.py": f"""import os
from flask import Flask

app = Flask(__name__)
app.secret_key = "flask-secret-{_rand(20)}"

# TODO: move to env vars
GOOGLE_API_KEY = "AIzaSy{_rand(33)}"
SENDGRID_KEY = "SG.{_rand(22)}.{_rand(22)}"

@app.route("/")
def index():
    return "Hello World"

if __name__ == "__main__":
    app.run(debug=True)
""",
        "src/auth.py": f"""# Authentication module
import jwt

SECRET = "Bearer {_rand(40)}"
TWILIO_SID = "AC{_rand(32)}"
TWILIO_KEY = "SK{''.join(random.choices('0123456789abcdef', k=32))}"

def verify_token(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])

# Basic auth for internal API
INTERNAL_AUTH = "Basic {_rand(30)}"
""",
        "deploy/docker-compose.yml": f"""version: '3.8'
services:
  app:
    build: .
    environment:
      - DATABASE_URL=mysql://root:rootpassword@db:3306/app
      - MAILGUN_KEY=key-{''.join(random.choices(string.ascii_lowercase + string.digits, k=32))}
      - HEROKU_API_KEY=heroku-{_rand(8)[:8]}-{''.join(random.choices('0123456789abcdef', k=4))}-{''.join(random.choices('0123456789abcdef', k=4))}-{''.join(random.choices('0123456789abcdef', k=4))}-{''.join(random.choices('0123456789abcdef', k=12))}
  db:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
""",
        "scripts/setup.sh": f"""#!/bin/bash
export GITLAB_TOKEN="glpat-{_rand(20)}"
export GITHUB_OAUTH="gho_{_rand(36)}"
export SLACK_WEBHOOK="https://hooks.slack.com/services/T01234567/B01234567/{_rand(24)}"
echo "Setup complete"
""",
        "keys/service_account.json": f"""{{
  "type": "service_account",
  "project_id": "my-project-123",
  "private_key_id": "{_rand(40)}",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA{_rand(60)}\\n-----END RSA PRIVATE KEY-----",
  "client_email": "service@my-project-123.iam.gserviceaccount.com",
  "client_id": "123456789",
  "token_uri": "https://oauth2.googleapis.com/token"
}}""",
        "notes.txt": f"""Team meeting notes:
- New API key for prod: {_rand(40)}
- password: not-important-just-notes
- JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.{_rand(27)}
""",
        "src/utils/constants.py": """# Application constants — no secrets here
MAX_RETRIES = 3
TIMEOUT_SECONDS = 30
DEFAULT_PAGE_SIZE = 25
APP_NAME = "MyApp"
VERSION = "1.2.3"
BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
""",
        "README.md": """# My Application
A sample app for testing.
Run with `python src/app.py`.
""",
    }

    for relpath, content in files.items():
        fpath = os.path.join(base_path, relpath)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write(content)

    # Initialize git repo with history
    try:
        import git
        repo = git.Repo.init(base_path)

        # First commit — "initial" with some secrets
        old_env = os.path.join(base_path, ".env.old")
        with open(old_env, "w") as f:
            f.write(f"OLD_AWS_KEY=AKIAIOSFODNN7OLDEXAM\nOLD_SECRET=wJalrXUtnFEMI_{_rand(30)}\n")
        repo.index.add([".env.old"])
        repo.index.commit("Initial commit with old credentials", author=git.Actor("Dev", "dev@example.com"))

        # Second commit — remove old, add new files
        if os.path.exists(old_env):
            repo.index.remove([".env.old"])
            os.remove(old_env)
        for relpath in files:
            repo.index.add([relpath])
        repo.index.commit("Add application code", author=git.Actor("Dev", "dev@example.com"))

        # Third commit — add another secret that gets "fixed"
        leaked = os.path.join(base_path, "src", "leaked_temp.py")
        with open(leaked, "w") as f:
            f.write(f'STRIPE_KEY = "sk_live_{_rand(24)}"\n')
        repo.index.add(["src/leaked_temp.py"])
        repo.index.commit("Accidentally add stripe key", author=git.Actor("Junior", "junior@example.com"))

        # Fourth commit — remove it
        os.remove(leaked)
        repo.index.remove(["src/leaked_temp.py"])
        repo.index.commit("Remove leaked stripe key", author=git.Actor("Senior", "senior@example.com"))

        log("info", "test_repo", f"Test repo created at {base_path} with {len(files)} files and git history")
    except ImportError:
        log("warning", "test_repo", "GitPython not available — created files without git history")
    except Exception as e:
        log("warning", "test_repo", f"Git init issue: {e} — files still created")

    return os.path.abspath(base_path)
