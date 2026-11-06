#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Test the built add-on console space against two disposable loopback HTTPS origins.

Run after the web build with Playwright installed. Synthetic credentials, fake
microphone, and WebSocket echo only: no fleet connection or GPU inference.
"""
import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'ui/apps/web/dist'
TOKEN = 'synthetic-console-token-not-a-credential'


@contextmanager
def peers():
    state = {'minted': 0, 'redeemed': [], 'errors': []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, body=b'', status=200, content_type='text/html', headers=None):
            if isinstance(body, dict):
                body, content_type = json.dumps(body).encode(), 'application/json'
            if isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.server is console and self.path == '/api/addons/rhaddon/ui-session':
                if self.headers.get('Authorization') != 'Bearer '+TOKEN:
                    return self.reply(status=401)
                state['minted'] += 1
                path = '/__noo/session?code=one-use-'+str(state['minted'])
                return self.reply({'port': voice.server_port, 'path': path, 'url': voice_origin+path},
                    headers={'Set-Cookie': 'noo_handoff=synthetic-binding; Path=/__noo/session; Secure; HttpOnly; SameSite=Strict'})
            self.reply(status=404)

        def do_GET(self):
            try:
                self.get()
            except Exception as e:
                state['errors'].append(type(e).__name__)
                self.reply(status=500)

        def get(self):
            path = urlsplit(self.path).path
            if self.server is console:
                if path == '/api/addons/ui':
                    return self.reply({'uis': [{'addon': 'rhaddon', 'title': 'Example workspace', 'port': voice.server_port,
                        'url_base': voice_origin, 'can_open': True, 'console_path': '/example-space',
                        'frame_permissions': ['microphone', 'autoplay']}]})
                if path == '/auth/me':
                    return self.reply({'username': 'alice', 'scopes': ['read']})
                file = DIST / ('index.html' if path == '/example-space' else path.lstrip('/'))
                if not file.resolve().is_relative_to(DIST.resolve()) or not file.is_file():
                    return self.reply(status=404)
                headers = {}
                if path == '/example-space':
                    headers = {'Content-Security-Policy': (
                        "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
                        "script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; "
                        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; frame-src "+voice_origin),
                        'Permissions-Policy': f'geolocation=(), camera=(), microphone=(self "{voice_origin}"), autoplay=(self "{voice_origin}"), fullscreen=(), clipboard-write=()',
                        'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer'}
                body = file.read_bytes()
                if path == '/example-space':
                    body = body.replace(b'<head>', b'<head><meta name="noo-addon-space" content="rhaddon">', 1)
                return self.reply(body, content_type=mimetypes.guess_type(file)[0] or 'application/octet-stream', headers=headers)
            assert not self.headers.get('Authorization'), 'Bearer leaked to frame'
            if path == '/__noo/session':
                assert self.headers.get('Sec-Fetch-Mode') == 'navigate'
                assert self.headers.get('Sec-Fetch-Site') == 'same-site'
                assert 'noo_handoff=synthetic-binding' in self.headers.get('Cookie', '')
                assert self.path not in state['redeemed']
                state['redeemed'].append(self.path)
                return self.reply(status=302, headers={'Location': '/',
                    'Set-Cookie': 'noo_voice=synthetic-session; Path=/; HttpOnly; Secure; SameSite=Strict'})
            if path == '/probe.js':
                return self.reply('''
 document.querySelector('button').onclick = async () => {
   try {
     try { parent.localStorage.getItem('pai_token'); throw Error('parent storage readable'); }
     catch (e) { if(e.name !== 'SecurityError') throw e; }
     if(localStorage.getItem('pai_token')) throw Error('console storage shared');
     const stream = await navigator.mediaDevices.getUserMedia({audio:true});
     const socket = new WebSocket(location.origin.replace('https:', 'wss:')+'/stream');
     socket.onopen = () => socket.send('synthetic-audio-frame');
     socket.onmessage = e => {
       document.querySelector('output').textContent = e.data;
       stream.getTracks().forEach(t => t.stop()); socket.close();
     };
   } catch(e) { document.querySelector('output').textContent = e.name + ': ' + e.message; }
 };''', content_type='application/javascript')
            assert 'noo_voice=synthetic-session' in self.headers.get('Cookie', '')
            self.reply('<button>Test microphone</button><output></output><script src="/probe.js"></script>',
                headers={'Content-Security-Policy': f"default-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors {console_origin}"})

    with tempfile.TemporaryDirectory(prefix='noo-voice-browser-') as tmp:
        cert, key = Path(tmp)/'cert.pem', Path(tmp)/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        console = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        voice = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        console_origin = f'https://127.0.0.1:{console.server_port}'
        voice_origin = f'https://127.0.0.1:{voice.server_port}'
        threads = []
        for server in (console, voice):
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        try:
            yield console_origin, voice_origin, state
        finally:
            for server, thread in zip((console, voice), threads):
                server.shutdown()
                server.server_close()
                thread.join(5)


async def main():
    assert (DIST/'index.html').is_file(), 'Build the console first'
    with peers() as (console, voice, state):
        async with async_playwright() as p:
            browser = await p.chromium.launch(executable_path=os.getenv('NOO_TEST_CHROMIUM'),
                args=['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'])
            context = await browser.new_context(ignore_https_errors=True)
            context.set_default_timeout(15000)
            await context.grant_permissions(['microphone'], origin=voice)
            await context.add_init_script(f"if(location.origin === '{console}') localStorage.setItem('pai_token', '{TOKEN}')")
            async def socket(ws):
                ws.on_message(lambda value: ws.send('voice-returned' if value == 'synthetic-audio-frame' else 'bad-frame'))
            await context.route_web_socket(voice.replace('https:', 'wss:')+'/stream', socket)
            page = await context.new_page()
            await page.goto(console+'/example-space')
            await page.get_by_role('button', name='Open', exact=True).click()
            frame = page.frame_locator('iframe')
            await frame.get_by_role('button', name='Test microphone').click()
            try:
                await frame.locator('output').filter(has_text='voice-returned').wait_for()
            except Exception as error:
                raise AssertionError(await frame.locator('output').inner_text()) from error
            assert page.url == console+'/example-space'
            await page.reload()
            assert await page.locator('iframe').count() == 0
            await page.get_by_role('button', name='Open', exact=True).click()
            await page.frame_locator('iframe').get_by_role('button', name='Test microphone').wait_for()
            assert state['minted'] == 2 and len(state['redeemed']) == 2
            await page.evaluate("window.dispatchEvent(new Event('metis:logout'))")
            await page.locator('iframe').wait_for(state='detached')
            assert not state['errors'], state['errors']
            await browser.close()
    print(json.dumps({'passed': True, 'checks': ['friendly URL', 'browser-bound iframe handoff',
        'origin isolation', 'microphone delegation', 'WebSocket roundtrip', 'fresh handoff on reload', 'logout unmount'],
        'live_gateway': False, 'gpu_inference': False}))


if __name__ == '__main__':
    asyncio.run(main())
