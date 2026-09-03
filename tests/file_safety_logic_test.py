from dataclasses import dataclass


@dataclass
class State:
    start: int = 0
    count: int = 0
    streak: int = 0


def create(state: State, now: int, requested: int, *, unlocked: bool, limit: int = 5,
           window: int = 300, terminate_after: int = 3):
    """Executable model of RotateFileWindow + CanCreateFiles + RecordCreatedFiles."""
    if not unlocked or requested <= 0:
        return "NOT_GUARDED"
    if state.start <= 0:
        state.start = now
        state.count = 0
    elif now >= state.start + window:
        elapsed = (now - state.start) // window
        previous_full = state.count >= limit
        if not previous_full or elapsed > 1:
            state.streak = 0
        state.start += elapsed * window
        state.count = 0
    if requested > limit or state.count + requested > limit:
        return "BLOCKED"
    state.count += requested
    if state.count == limit:
        state.streak += 1
        if state.streak >= terminate_after:
            return "TERMINATED"
    return "ALLOWED"


# Exactly three adjacent full windows terminate on the third full window.
state = State()
assert create(state, 1, 5, unlocked=True) == "ALLOWED"
assert create(state, 301, 5, unlocked=True) == "ALLOWED"
assert create(state, 601, 5, unlocked=True) == "TERMINATED"

# A partial intervening window resets the consecutive-full-window streak.
state = State()
assert create(state, 1, 5, unlocked=True) == "ALLOWED"
assert create(state, 301, 3, unlocked=True) == "ALLOWED"
assert create(state, 601, 5, unlocked=True) == "ALLOWED"
assert state.streak == 1

# Skipping a complete window resets the streak.
state = State()
assert create(state, 1, 5, unlocked=True) == "ALLOWED"
assert create(state, 601, 5, unlocked=True) == "ALLOWED"
assert state.streak == 1

# Reads, navigation, other actions and existing-file writes request zero new files.
snapshot = State(start=1, count=5, streak=1)
assert create(snapshot, 301, 0, unlocked=True) == "NOT_GUARDED"
assert snapshot == State(start=1, count=5, streak=1)

# The entire file guard is inactive while the session is locked.
snapshot = State(start=1, count=5, streak=2)
assert create(snapshot, 601, 100, unlocked=False) == "NOT_GUARDED"
assert snapshot == State(start=1, count=5, streak=2)

print("PowerShell Guardian deterministic file-safety model: PASS")
