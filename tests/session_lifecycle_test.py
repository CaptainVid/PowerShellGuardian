from dataclasses import dataclass


TIMEOUT_SECONDS = 60 * 60


@dataclass
class Session:
    session_id: str
    token: str
    approved: bool = True
    denied: bool = False
    unlocked: bool = False
    last_active: int = 0
    expires: int = TIMEOUT_SECONDS


def touch(session: Session, now: int) -> None:
    session.last_active = now
    session.expires = now + TIMEOUT_SECONDS


def switch_access(session: Session, now: int) -> tuple[str, str]:
    original_identity = (session.session_id, session.token)
    session.unlocked = not session.unlocked
    touch(session, now)
    assert (session.session_id, session.token) == original_identity
    return original_identity


# A session can execute approved locked commands and later be unlocked without rotation.
session = Session("PSG-123-ABCDEF", "a" * 64)
touch(session, 100)
touch(session, 200)
identity = switch_access(session, 300)
assert session.unlocked is True
assert identity == ("PSG-123-ABCDEF", "a" * 64)
assert session.expires == 300 + TIMEOUT_SECONDS

# A successful status lookup is activity even when the session remains locked.
locked = Session("PSG-456-FEDCBA", "b" * 64, unlocked=False, expires=10)
touch(locked, 9)
assert locked.unlocked is False
assert locked.expires == 9 + TIMEOUT_SECONDS

# History cleanup removes exactly SUCCESS and REJECTED.
statuses = ["WAITING APPROVAL", "RUNNING", "SUCCESS", "REJECTED", "FAILED", "BLOCKED"]
remaining = [status for status in statuses if status not in {"SUCCESS", "REJECTED"}]
assert remaining == ["WAITING APPROVAL", "RUNNING", "FAILED", "BLOCKED"]

print("PowerShell Guardian session lifecycle/history model: PASS")
