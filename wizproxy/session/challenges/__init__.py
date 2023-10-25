from wizproxy.proto import SignedMessage

from . import client_sig
from .client_sig import ClientSig


def process_challenge(sig: ClientSig, message: SignedMessage) -> int:
    challenge_type = message.challenge_type
    if challenge_type == client_sig.CHALLENGE_ID:
        if sig is None:
            return None
        return client_sig.challenge(sig, message.challenge_buf)

    else:
        raise ValueError(f"unknown crypto challenge: {challenge_type}")
