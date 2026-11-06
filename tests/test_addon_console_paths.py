# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Every literal or named core routing prefix reserves its console namespace."""
from pathlib import Path
import re
from _rust_src import own_code

ROOT = Path(__file__).resolve().parents[1]


def route_segments(source, constants):
    source = own_code(source)
    found = set()
    for value in re.findall(r'\.(?:route|nest|nest_service|route_service)\(\s*("[^"]*"|[A-Z][A-Z_0-9]*)\s*,', source):
        path = value[1:-1] if value.startswith('"') else constants[value]
        segment = path.lstrip('/').split('/')[0]
        if segment and not segment.startswith('{'):
            found.add(segment)
    return found


def reserved():
    source = (ROOT / 'crates/addon-manifest/src/lib.rs').read_text()
    block = source.split('pub const CONSOLE_RESERVED_SEGMENTS:', 1)[1].split('];', 1)[0]
    return set(re.findall(r'"([^"]+)"', block))


def test_every_core_namespace_is_reserved():
    sources = [p.read_text() for p in (ROOT / 'gateway-rust/src').rglob('*.rs')]
    constants = dict(re.findall(r'const\s+([A-Z][A-Z_0-9]*)\s*:\s*&str\s*=\s*"([^"]+)"', '\n'.join(sources)))
    segments = set()
    for source in sources:
        if 'openapi-drift: not-gateway-routes' in source[:4000]:
            continue
        segments |= route_segments(source, constants)
    assert not segments - reserved(), f'Unreserved core routes: {sorted(segments - reserved())}'


def test_new_route_mutant_is_detected_in_all_registration_forms():
    for method in ('route', 'nest', 'nest_service', 'route_service'):
        assert route_segments(f'router.{method}("/new-core-route/x", handler)', {}) - reserved() == {'new-core-route'}
        assert route_segments(f'router.{method}(NEW_ROUTE, handler)', {'NEW_ROUTE': '/new-core-route'}) - reserved() == {'new-core-route'}
