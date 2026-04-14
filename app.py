import os
import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, email: str = Form(...)):
    breaches = []
    error = None

    if not HIBP_API_KEY:
        error = "HIBP_API_KEY er ikke sat. Tilføj den som env var."
    else:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    HIBP_URL.format(email),
                    headers={
                        "hibp-api-key": HIBP_API_KEY,
                        "user-agent": "sletmig-dk",
                    },
                    params={"truncateResponse": "false"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    breaches = resp.json()
                elif resp.status_code == 404:
                    breaches = []
                elif resp.status_code == 401:
                    error = "Ugyldig API-nøgle."
                else:
                    error = f"HIBP API fejlede: {resp.status_code}"
        except Exception as e:
            error = f"Forbindelsesfejl: {e}"

    return templates.TemplateResponse("results.html", {
        "request": request,
        "email": email,
        "breaches": breaches,
        "error": error,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
