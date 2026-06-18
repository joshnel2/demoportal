# Summit Team Apparel — Admin Portal (Demo)

A **visual demo clone** of a manufacturing/ops admin dashboard. This is a
front-end-only showcase: sign in with **any username and password** and click
through every section.

- All numbers are fictional (inflated sample data) and all company / client /
  employee names are made up. Nothing here maps to a real business.
- Functionality that writes data (uploads, comments, exports, GitHub/Azure
  sync) is intentionally disabled — this is a look-and-feel demo only.
- Data is read from the bundled `data.json`; there is no backend.

## Run locally

```bash
python3 -m http.server 8753
# open http://localhost:8753
```

## Files

| File | Purpose |
|------|---------|
| `index.html` | Login + app shell |
| `admin.js`   | All dashboard rendering + (bypassed) login |
| `admin.css`  | Styles |
| `crypto.js`  | Unused in demo (kept for parity) |
| `data.json`  | Sample dashboard data |
