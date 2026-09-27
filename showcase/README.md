# LogLeak Showcase — Tiny Clinic API

A minimal FastAPI app that **deliberately leaks PII into logs**, used to
demonstrate what LogLeak detects and fixes.

```
showcase/
├── app_leaky.py        ← version with 4 planted PII leaks
├── app_clean.py        ← same app after LogLeak fixes
├── run_demo.py         ← runs a scan on app_leaky, prints a report
├── requirements.txt
└── README.md
```

## Quick start

```bash
cd showcase
pip install -r requirements.txt

# See the leaks detected live
python run_demo.py

# Run the leaky server (ctrl-c to stop)
uvicorn app_leaky:app --reload

# Run the clean server
uvicorn app_clean:app --reload
```

## The 4 planted leaks

| # | File | Line | Kind | How it leaks |
|---|------|------|------|--------------|
| L1 | `app_leaky.py` | `register_patient` | email | `logger.info("Registered %s", email)` |
| L2 | `app_leaky.py` | `charge_card` | card | `logger.debug("Charging %s", card_number)` |
| L3 | `app_leaky.py` | `charge_card` | card | `raise ValueError(f"Declined: {card_number}")` — card in exception |
| L4 | `app_leaky.py` | `login` | jwt | `print(f"issued token {token}")` — forgotten debug print |

`app_clean.py` fixes all four:
- L1 / L2: log only safe surrogate fields (patient ID, masked last-4)
- L3: exception message no longer includes the raw number
- L4: debug print removed; token stays in the return value only
