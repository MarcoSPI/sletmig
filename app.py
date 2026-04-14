import os
import secrets
import httpx
import anthropic
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import quote

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", secrets.token_hex(32)))
templates = Jinja2Templates(directory="templates")

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
SERPAPI_KEY = os.getenv("SERPAPI_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
APP_USER = os.getenv("APP_USER", "marco")
APP_PASS = os.getenv("APP_PASS", "")


def kræv_login(request: Request):
    if not request.session.get("logget_ind"):
        raise Exception("ikke logget ind")


def er_logget_ind(request: Request) -> bool:
    return bool(request.session.get("logget_ind"))


# ── Login ──────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_side(request: Request):
    if er_logget_ind(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "fejl": None})


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, brugernavn: str = Form(...), adgangskode: str = Form(...)):
    ok_user = secrets.compare_digest(brugernavn, APP_USER)
    ok_pass = secrets.compare_digest(adgangskode, APP_PASS)
    if ok_user and ok_pass:
        request.session["logget_ind"] = True
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "fejl": "Forkert brugernavn eller adgangskode"})


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ── Beskyttede sider ───────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not er_logget_ind(request):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, navn: str = Form(...), email: str = Form(...)):
    if not er_logget_ind(request):
        return RedirectResponse("/login", status_code=302)

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

    # Google synlighed via SerpAPI
    google_results = []
    google_error = None
    if SERPAPI_KEY:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://serpapi.com/search",
                    params={"q": f'"{navn}"', "api_key": SERPAPI_KEY, "num": 10, "hl": "da", "gl": "dk"},
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    google_results = data.get("organic_results", [])
                else:
                    google_error = f"SerpAPI fejl: {resp.status_code}"
        except Exception as e:
            google_error = f"Søgefejl: {e}"
    else:
        google_error = "SERPAPI_KEY mangler"

    navn_enc = quote(navn)
    databrokers = [
        {"navn": "krak.dk",        "url": f"https://www.krak.dk/person/resultat/{navn_enc}",       "dpo": "dataprotectionoffice@krak.dk", "mitid": True},
        {"navn": "eniro.dk",       "url": f"https://www.eniro.dk/person/?what={navn_enc}",          "dpo": "privatpersoner@eniro.com",     "mitid": False},
        {"navn": "ratsit.se",      "url": f"https://www.ratsit.se/search?query={navn_enc}",         "dpo": "kundservice@ratsit.se",        "mitid": False},
        {"navn": "degulesider.dk", "url": f"https://www.degulesider.dk/person/?what={navn_enc}",    "dpo": "dpo@degulesider.dk",           "mitid": False},
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
):
    if not er_logget_ind(request):
        return RedirectResponse("/login", status_code=302)

    site_map = {
        "krak":        {"navn": "Krak.dk",       "dpo": "dataprotectionoffice@krak.dk"},
        "eniro":       {"navn": "Eniro.dk",       "dpo": "privatpersoner@eniro.com"},
        "ratsit":      {"navn": "Ratsit.se",      "dpo": "kundservice@ratsit.se"},
        "degulesider": {"navn": "De Gule Sider",  "dpo": "dpo@degulesider.dk"},
    }
    valgte = {k: v for k, v in site_map.items() if request.form and (await request.form()).get(k)}

    # Genbyg valgte fra form-felterne direkte
    valgte = {}
    if krak: valgte["krak"] = site_map["krak"]
    if eniro: valgte["eniro"] = site_map["eniro"]
    if ratsit: valgte["ratsit"] = site_map["ratsit"]
    if degulesider: valgte["degulesider"] = site_map["degulesider"]

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
