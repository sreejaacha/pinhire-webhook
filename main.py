
import os
import json
import hmac
import hashlib
import time
import asyncio

from decimal import Decimal, InvalidOperation
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="PinHire Webhook")

# Read the signing key from the environment
SECRET_KEY = os.getenv(
    "PINHIRE_SECRET",
    "SEED-7093-PH-4D3E"
).encode()

REFUND_LIMIT = Decimal("175")
LOCK_TTL = 120

processed_transactions = {}
transaction_lock = asyncio.Lock()


def verify_hmac(raw_body, signature):
    if not signature:
        return False

    signature = signature.removeprefix("sha256=")

    expected_signature = hmac.new(
        SECRET_KEY,
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(
        expected_signature,
        signature
    )


def validate_refund(amount):
    try:
        amount = Decimal(str(amount))

        if not amount.is_finite():
            return False

        return Decimal("0") < amount <= REFUND_LIMIT

    except (InvalidOperation, TypeError, ValueError):
        return False


async def check_idempotency(tx_ref):
    current_time = time.monotonic()

    async with transaction_lock:

        expired = [
            key for key, timestamp in processed_transactions.items()
            if current_time - timestamp >= LOCK_TTL
        ]

        for key in expired:
            del processed_transactions[key]

        if tx_ref in processed_transactions:
            return False

        processed_transactions[tx_ref] = current_time
        return True


@app.get("/")
async def home():
    return {"status": "online"}


@app.post("/api/guard")
async def guard(request: Request):

    raw_body = await request.body()

    signature = request.headers.get(
        "x-pinhire-hmac-7093"
    )

    if not verify_hmac(raw_body, signature):
        return JSONResponse(
            status_code=401,
            content={"error": "Invalid signature"}
        )

    try:
        data = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid JSON"}
        )

    if not isinstance(data, dict):
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid request body"}
        )

    event = data.get("event")
    payload = data.get("payload")

    if not isinstance(payload, dict):
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid payload"}
        )

    # FAQ event
    if event == "faq.query":
        return {
            "status": "success",
            "answer": (
                "Refunds are subject to verification. "
                "The maximum permitted refund is 175 AED."
            )
        }

    # Refund event
    if event == "refund.requested":

        tx_ref = payload.get("tx_ref_7093")
        amount = payload.get("refund_aed")

        if not isinstance(tx_ref, str) or not tx_ref.strip():
            return JSONResponse(
                status_code=400,
                content={"error": "Missing transaction reference"}
            )

        if not validate_refund(amount):
            return JSONResponse(
                status_code=422,
                content={"error": "Refund amount exceeds limit or is invalid"}
            )

        is_new = await check_idempotency(tx_ref)

        if not is_new:
            return JSONResponse(
                status_code=409,
                content={"status": "duplicate"}
            )

        return {
            "status": "processed",
            "tx_ref_7093": tx_ref,
            "refund_aed": str(Decimal(str(amount)))
        }

    return JSONResponse(
        status_code=400,
        content={"error": "Unsupported event"}
    )
