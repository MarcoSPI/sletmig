import os
import secrets
import httpx
import anthropic
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from urllib.parse import quote

app = FastAPI()
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
APP_USER = os.getenv("APP_USER", "marco")
APP_PASS = os.getenv("APP_PASS", "")


def check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    ok_user = secrets.compare_digest(credentials.username, APP_USER)
    ok_pass = secrets.compare_digest(credentials.password, APP_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, _=Depends(check_auth)):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    navn: str = Form(...),
    email: str = Form(...),
    _=Depends(check_auth),
):
    # HIBP scan
    breaches = []
    hibp_error = None
    if not HIBP_API_KEY:
        hibp_error = "HIBP_API_KEY mangler"
    else:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={"hibp-api-key": HIBP_API_KEY, "user-agent": "sletmig-dk"},
                    params={"truncateResponse": "false"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    breaches = resp.json()
                elif resp.status_code == 404:
                    breaches = []
                else:
                    hibp_error = f"HIBP fejl: {resp.status_code}"
        except Exception as e:
            hibp_error = f"Forbindelsesfejl: {e}"

    # Google synlighed
    google_results = []
    google_error = None
    if GOOGLE_API_KEY and GOOGLE_CSE_ID:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={"key": GOOGLE_API_KEY, "cx": GOOGLE_CSE_ID, "q": f'"{navn}"', "num": 10},
                    timeout=10,
                )
                if resp.status_code == 200:
                    google_results = resp.json().get("items", [])
                else:
                    google_error = f"Google API fejl: {resp.status_code}"
        except Exception as e:
            google_error = f"Google fejl: {e}"
    else:
        google_error = "Google API ikke konfigureret endnu"

    # Databroker links med præudfyldt søgning
    navn_enc = quote(navn)
    databrokers = [
        {"navn": "krak.dk",         "url": f"https://www.krak.dk/person/resultat/{navn_enc}", "dpo": "dataprotectionoffice@krak.dk",  "mitid": True},
        {"navn": "eniro.dk",        "url": f"https://www.eniro.dk/person/?what={navn_enc}",    "dpo": "privatpersoner@eniro.com",        "mitid": False},
        {"navn": "ratsit.se",       "url": f"https://www.ratsit.se/search?query={navn_enc}",   "dpo": "kundservice@ratsit.se",           "mitid": False},
        {"navn": "degulesider.dk",  "url": f"https://www.degulesider.dk/person/?what={navn_enc}", "dpo": "dpo@degulesider.dk",          "mitid": False},
    ]

    return templates.TemplateResponse("results.html", {
        "request": request,
        "navn": navn,
        "email": email,
        "breaches": breaches,
        "hibp_error": hibp_error,
        "google_results": google_results,
        "google_error": google_error,
        "databrokers": databrokers,
    })


@app.post("/generer-emails", response_class=HTMLResponse)
async def generer_emails(
    request: Request,
    navn: str = Form(...),
    email: str = Form(...),
    krak: str = Form(default=""),
    eniro: str = Form(default=""),
    ratsit: str = Form(default=""),
    degulesider: str = Form(default=""),
    _=Depends(check_auth),
):
    site_map = {
        "krak":        {"navn": "Krak.dk",         "dpo": "dataprotectionoffice@krak.dk"},
        "eniro":       {"navn": "Eniro.dk",         "dpo": "privatpersoner@eniro.com"},
        "ratsit":      {"navn": "Ratsit.se",        "dpo": "kundservice@ratsit.se"},
        "degulesider": {"navn": "De Gule Sider",    "dpo": "dpo@degulesider.dk"},
    }
    valgte = {k: v for k, v in site_map.items() if locals().get(k)}

    emails = []
    if ANTHROPIC_API_KEY and valgte:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        for site in valgte.values():
            prompt = f"""Skriv en kort, professionel GDPR Art. 17 sletanmodning på dansk.

Afsender: {navn}
Modtager: {site['navn']} ({site['dpo']})

Krav:
- Reference til GDPR Art. 17 (ret til sletning)
- Bed om sletning af ALLE personoplysninger om {navn}
- Bed om skriftlig bekræftelse inden 30 dage
- Professionel og direkte tone
- Max 120 ord
- Skriv KUN emailteksten (inkl. emnefeltet som første linje med "Emne: ...")"""

            svar = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}]
            )
            emails.append({
                "site": site["navn"],
                "dpo": site["dpo"],
                "tekst": svar.content[0].text.strip(),
            })
    elif not ANTHROPIC_API_KEY:
        emails = [{"site": s["navn"], "dpo": s["dpo"], "tekst": "ANTHROPIC_API_KEY mangler"} for s in valgte.values()]

    return templates.TemplateResponse("emails.html", {
        "request": request,
        "navn": navn,
        "emails": emails,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
