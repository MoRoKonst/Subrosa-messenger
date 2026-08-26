"""
Shared fixtures for the security regression tests (docs/CI_SAST_PLAN.md,
"Security regression tests" section). DB_PATH must be set before `server`
is ever imported -- the module reads it once at import time (server.py:253).
"""
import os
import sys
import tempfile

import pytest
import pytest_asyncio

_TMP_DB_FD, _TMP_DB_PATH = tempfile.mkstemp(suffix=".db", prefix="subrosa_test_")
os.close(_TMP_DB_FD)
os.environ["DB_PATH"] = _TMP_DB_PATH
os.environ.setdefault("MAX_REGISTERED_USERS", "0")
# PoW is a separate, already-tested concern (cost paid by real clients) --
# disabled here so registration in these tests is fast and deterministic.
os.environ.setdefault("POW_DIFFICULTY_BITS", "0")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# server.py rebinds sys.stdout/stderr to its own TextIOWrapper at import
# time (for consistent UTF-8 console output when run standalone) -- that
# fights pytest's own stdout/stderr capture machinery if left in place
# during a test session. Just reassigning sys.stdout back isn't enough:
# the orphaned TextIOWrapper still owns pytest's underlying capture buffer
# and closes it (via __del__) once garbage-collected, which later crashes
# pytest's own capture teardown ("I/O operation on closed file"). detach()
# first so the wrapper releases the buffer without closing it.
_orig_stdout, _orig_stderr = sys.stdout, sys.stderr
import server  # noqa: E402
if sys.stdout is not _orig_stdout:
    try:
        sys.stdout.detach()
    except Exception:
        pass
if sys.stderr is not _orig_stderr:
    try:
        sys.stderr.detach()
    except Exception:
        pass
sys.stdout, sys.stderr = _orig_stdout, _orig_stderr

server._db_setup_sync()


@pytest.fixture(autouse=True)
def reset_state():
    """Every test starts from a clean slate -- both the in-memory routing
    state and the on-disk tables the invariants under test actually touch."""
    server.clients.clear()
    server.authenticated_users.clear()
    server.token_to_ws.clear()
    server.token_pending.clear()
    server.token_pending_created.clear()
    server.ws_to_tokens.clear()
    server.known_tokens.clear()
    server.spent_tokens.clear()
    server.rate_limits.clear()
    with server.db_connect() as conn:
        for table in (
            "registered_fingerprints",
            "revoked_fingerprints",
            "server_access_codes",
            "totp_recovery_codes",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    yield


@pytest_asyncio.fixture
async def running_server():
    """Real websockets.serve() bound to an ephemeral port, running the
    actual server.handle_client -- exercises the real production code path,
    not a reimplementation of it."""
    async with server.websockets.serve(server.handle_client, "127.0.0.1", 0) as ws_server:
        port = ws_server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
