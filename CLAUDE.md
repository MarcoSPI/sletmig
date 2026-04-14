# Sletmig — Projektinfo

## Hvad er det?
Dansk service der hjælper brugere med at slette deres digitale fodspor. Finder eksponering på danske/nordiske sites og genererer GDPR Art. 17 emails.

## Stack
- FastAPI + Jinja2
- Peewee ORM (SQLite lokalt, PostgreSQL på Railway)
- HTMX
- Anthropic Claude API

## Git
- Repo: https://github.com/MarcoSPI/sletmig
- Branch: main

## Railway
- Project: sletmig
- Environment: production
- Deploy: `railway up --service sletmig`
- Link: `railway link -p c47a7c3a-fcd3-4e9a-806f-178f51a3c83c -w 42273a3e-c141-4ec0-b6a9-15b611eaff72`
