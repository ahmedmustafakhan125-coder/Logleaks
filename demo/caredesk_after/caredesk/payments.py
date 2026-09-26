"""payments.py — card payment processing."""
from __future__ import annotations

import logging

from caredesk.models import Order, PaymentCard

logger = logging.getLogger(__name__)

_orders: dict[str, Order] = {}
_order_counter = 3000


def charge_card(
    patient_id: str,
    card: PaymentCard,
    amount: int,
    description: str,
) -> Order:
    """Charge a card and return the resulting Order."""
    global _order_counter
    card_number = card.card_number
    card_last4  = card_number[-4:] if len(card_number) >= 4 else card_number

    logger.debug("Charging card ending %s for %s", card_last4, amount)

    # Simulate a decline when CVV is "000" (test-mode decline signal)
    if card.cvv == "000":
        try:
            raise ValueError(f"Card declined for patient {patient_id}")
        except ValueError:
            logger.exception("payment failed for patient %s", patient_id)
            raise

    _order_counter += 1
    order_id = f"ORD-{_order_counter}"
    order = Order(
        order_id=order_id,
        patient_id=patient_id,
        amount=amount,
        description=description,
    )
    _orders[order_id] = order
    # Log with the useful order ID. The decoy ORD-4111111111111112 (fails Luhn)
    # is referenced in the description field and must NOT be flagged as a card.
    logger.info(
        "Order %s created for patient %s: %s paise (ref ORD-4111111111111112)",
        order_id, patient_id, amount,
    )
    return order


def get_order(order_id: str) -> Order | None:
    """Return the order with the given ID, or None."""
    order = _orders.get(order_id)
    if order is None:
        # Unwitnessed log path: only reached in error cases not covered by tests
        logger.error("Order %s not found in payment store", order_id)
    return order


def refund_order(order_id: str) -> bool:
    """Attempt a refund for an order. Returns True on success."""
    order = _orders.get(order_id)
    if order is None:
        # Unwitnessed: refund of non-existent order
        logger.error("Refund failed: order %s does not exist", order_id)
        return False
    logger.info("Refund issued for order %s (patient %s)", order_id, order.patient_id)
    return True
