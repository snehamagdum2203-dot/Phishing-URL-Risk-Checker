# Phishing URL Risk Checker API

A Python Flask REST API that checks URL text for selected suspicious patterns and returns a rule-based risk score with explanations. It does not open URLs or send network requests.

## Features

- URL structure checks without contacting the website
- Risk score from 0 to 100 with Low, Medium, or High level
- Reasons explaining the score
- Validation and JSON error responses
- Automated tests using Python `unittest`

## Risk scoring rules

| Signal | Points |
| --- | ---: |
| No HTTPS | 20 |
| `@` in the network location | 20 |
| Hostname is an IP address | 30 |
| More than four hostname parts | 15 |
| Selected account-related words | 15 |
| URL longer than 150 characters | 10 |

Scores are capped at 100. Low is 0–29, Medium is 30–59, and High is 60–100. These basic rules can produce false positives and false negatives; a low score does not prove a URL is safe.

## Setup on Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Start the API

```powershell
python app.py
```

The local development server uses `http://127.0.0.1:5000`.

## Endpoints

### Health check

`GET /health`

### Check a URL

`POST /api/v1/check`

JSON request body:

```json
{"url":"http://192.0.2.1/verify-account"}
```

PowerShell example:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/v1/check" -Method Post -ContentType "application/json" -Body '{"url":"http://192.0.2.1/verify-account"}'
```

The example uses a reserved documentation IP. The API only analyzes the text supplied; it does not contact the address.

The endpoint returns JSON errors for non-JSON requests, missing or invalid URLs, and URLs over 2048 characters.

## Run automated tests

With the virtual environment active:

```powershell
python -m unittest -v
```

## Files

- `app.py` — Flask API and scoring rules
- `test_app.py` — automated tests
- `requirements.txt` — dependency declaration
- `README.md` — project documentation
