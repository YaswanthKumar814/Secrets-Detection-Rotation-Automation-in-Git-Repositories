# GitGuard Dashboard Screenshots

Place presentation screenshots in this folder for the README and hackathon slides.

## Recommended captures

| File | Page | URL |
|------|------|-----|
| `01-overview.png` | Security Overview (home) | http://127.0.0.1:5000/ |
| `02-findings.png` | Secret Findings table | http://127.0.0.1:5000/findings |
| `03-analytics.png` | Risk Analytics charts | http://127.0.0.1:5000/analytics |
| `04-report.png` | HTML executive report | Open latest file in `reports_output/` |

## How to capture (Windows)

1. Run the demo:
   ```powershell
   python main.py demo
   python main.py dashboard
   ```
2. Open each URL in Chrome or Edge.
3. Press **Win + Shift + S** → select region → save PNG into this folder.
4. Use names above so README links stay consistent.

## Optional: report screenshot

Open the newest `reports_output/gitguard_report_*.html` in a browser and capture the executive summary section.

## Embedding in README

After adding images, reference them from the project root:

```markdown
![Overview](docs/screenshots/01-overview.png)
```
