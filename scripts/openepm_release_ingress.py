"""Verify the running release's public TLS, Browser and MCP entry points."""
from __future__ import annotations

import argparse
from contextlib import closing
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import signal
from socket import create_connection
import ssl
import stat
import sys
from urllib.parse import urlsplit


METADATA = '/.well-known/oauth-protected-resource'
APPLICATION = '/api/application/mcp'
PLATFORM = '/api/platform/mcp'
WORKSPACE = '/api/workspace/mcp'
BROWSER = ('/api/session-identity', '/api/applications', '/api/platform/browser/catalog')
CERTIFICATE_LIMIT = 65536
RESPONSE_LIMIT = 8192


class IngressCheckError(ValueError):
    pass


def published_endpoint(binding: str) -> tuple[str, int]:
    match = re.fullmatch(r'(\[[0-9A-Fa-f:]+\]|[0-9.]+):([0-9]{1,5})', binding)
    if not match:
        raise IngressCheckError('public proxy does not have a verified HTTPS port binding')
    try:
        host = ip_address(match[1].strip('[]'))
    except ValueError as error:
        raise IngressCheckError('public proxy has an invalid HTTPS port binding') from error
    port = int(match[2])
    if not 1 <= port <= 65535:
        raise IngressCheckError('public proxy has an invalid HTTPS port binding')
    if host.is_unspecified:
        return ('127.0.0.1' if host.version == 4 else '::1'), port
    return str(host), port


def certificate_context(path: Path) -> tuple[ssl.SSLContext, bytes]:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise IngressCheckError('public proxy configuration does not supply a regular certificate')
        data = file.read(CERTIFICATE_LIMIT + 1)
    match = re.search(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', data, re.DOTALL)
    if not match or len(data) > CERTIFICATE_LIMIT:
        raise IngressCheckError('public proxy configuration does not supply a bounded certificate')
    leaf = match[0].decode('ascii')
    context = ssl.create_default_context(cadata=leaf)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context, ssl.PEM_cert_to_DER_cert(leaf)


def request(endpoint, host, context, leaf, method, path):
    with create_connection(endpoint, timeout=4) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            if tls.getpeercert(binary_form=True) != leaf:
                raise IngressCheckError('public proxy presented a different release certificate')
            with closing(HTTPConnection(host, timeout=4)) as http:
                http.sock = tls
                body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}' if method == 'POST' else None
                http.request(method, path, body=body, headers={'Content-Type': 'application/json'})
                response = http.getresponse()
                data = response.read(RESPONSE_LIMIT + 1)
                if len(data) > RESPONSE_LIMIT:
                    raise IngressCheckError('public proxy returned an oversized response during verification')
                return response, data


def verify_ingress(binding: str, host: str, issuer: str, certificate: Path, profile: str) -> None:
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host) or '..' in host:
        raise IngressCheckError('public proxy hostname differs from the release contract')
    identity = urlsplit(issuer)
    if (identity.scheme != 'https' or not identity.hostname or identity.username is not None
            or identity.query or identity.fragment):
        raise IngressCheckError('public identity issuer differs from the release contract')
    endpoint = published_endpoint(binding)
    context, leaf = certificate_context(certificate)
    origin = 'https://' + host

    def send(method, path):
        return request(endpoint, host, context, leaf, method, path)

    for path in BROWSER:
        response, _ = send('GET', path)
        if response.status != 401 or response.getheader('WWW-Authenticate') or response.getheader('Location'):
            raise IngressCheckError('public Browser authorization boundary could not be verified')

    def check_document(path, resource):
        response, body = send('GET', path)
        try:
            document = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise IngressCheckError('public MCP OAuth metadata differs from the release') from error
        if (response.status != 200 or response.getheader('Content-Type') != 'application/json'
                or response.getheader('Cache-Control') != 'no-store'
                or not isinstance(document, dict) or document.get('resource') != origin + resource
                or document.get('authorization_servers') != [issuer]
                or document.get('bearer_methods_supported') != ['header']):
            raise IngressCheckError('public MCP OAuth metadata differs from the release')

    check_document(METADATA, APPLICATION)
    paths = (APPLICATION, PLATFORM, WORKSPACE) if profile == 'workspace' else (APPLICATION, PLATFORM)
    for path in paths:
        response, _ = send('POST', path)
        expected = f'Bearer resource_metadata="{origin}{METADATA}{path}", scope="openid profile"'
        if response.status != 401 or response.getheader('WWW-Authenticate') != expected:
            raise IngressCheckError('public MCP challenge differs from the release')
        check_document(METADATA + path, path)


def timeout(*_args):
    raise IngressCheckError('public ingress verification exceeded its deadline')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--issuer', required=True)
    parser.add_argument('--certificate', required=True, type=Path)
    parser.add_argument('--profile', required=True, choices=('core', 'workspace'))
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(25)
    try:
        verify_ingress(args.binding, args.host, args.issuer, args.certificate, args.profile)
    except IngressCheckError as error:
        print(f'epmctl: {error}', file=sys.stderr)
        return 69
    except (OSError, HTTPException, ValueError):
        print('epmctl: public proxy did not return a response over the configured TLS binding', file=sys.stderr)
        return 69
    finally:
        signal.alarm(0)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
