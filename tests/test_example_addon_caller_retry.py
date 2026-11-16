"""The example add-on's caller lookup retries once on a dropped connection.

Right after `noo stack restart --force` the add-on can query a Postgres that
is still restarting (rc.1 rehearsal: a 503 "cannot verify the caller" from the
add-on itself). Its lookup retries once; a second failure still raises, so the
handler answers 503 with the cause; any other error is never retried.
The server is loaded with a stand-in psycopg, so no database is needed.
"""
import importlib.util
import pathlib
import ssl
import sys
import types
from unittest import mock

import pytest

SERVER = pathlib.Path(__file__).resolve().parents[1] / "examples" / "example-addon" / "app" / "server.py"


class _OperationalError(Exception):
    pass


class _AdminShutdown(_OperationalError):  # psycopg.errors.AdminShutdown is an OperationalError
    pass


def _load(connect):
    fake = types.ModuleType("psycopg")
    fake.OperationalError = _OperationalError
    fake.connect = connect
    spec = importlib.util.spec_from_file_location("example_addon_server", SERVER)
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"psycopg": fake}), \
            mock.patch.object(ssl, "create_default_context", return_value=None):
        spec.loader.exec_module(mod)
    return mod


class _Conn:
    def __init__(self, row):
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, *a):
        return types.SimpleNamespace(fetchone=lambda: self.row)


def _connect_seq(outcomes):
    calls = []

    def connect(url, connect_timeout):
        calls.append(url)
        o = outcomes[len(calls) - 1]
        if isinstance(o, Exception):
            raise o
        return _Conn(o)

    return connect, calls


def _run(outcomes):
    connect, calls = _connect_seq(outcomes)
    mod = _load(connect)
    with mock.patch("builtins.open", mock.mock_open(read_data="postgresql://x\n")), \
            mock.patch.object(mod.time, "sleep") as sleep:
        try:
            return mod.caller_is_gateway("bearer"), calls, sleep
        except Exception as e:  # noqa: BLE001 - the test inspects it
            return e, calls, sleep


def test_one_dropped_connection_is_retried_and_answers():
    got, calls, sleep = _run([_AdminShutdown("terminating connection"), ("addon-caller:gw",)])
    assert got is True
    assert len(calls) == 2
    sleep.assert_called_once()


def test_a_second_drop_raises_for_the_503():
    got, calls, _ = _run([_AdminShutdown("a"), _AdminShutdown("b")])
    assert isinstance(got, _AdminShutdown)
    assert len(calls) == 2


def test_other_errors_are_not_retried():
    got, calls, sleep = _run([ValueError("bad query"), ("x",)])
    assert isinstance(got, ValueError)
    assert len(calls) == 1
    sleep.assert_not_called()


def test_no_row_is_still_a_refusal():
    got, calls, _ = _run([None])
    assert got is False
    assert len(calls) == 1
