"""Bounded deterministic numeric extraction from captured source bytes."""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
import json
import re

from .persistence_contract import NumericCell
from .postgres_policy_client_pdf import (
    SCHEMA_VERSION as CLIENT_PDF_SCHEMA, validate_manifest)


VERIFIER = 'captured-source-value-v1'
PDF_VERIFIER = 'client-pdf-source-value-v1'
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_PDF_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024


def validate_locator(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ValueError('POLICY_SOURCE_VALUE_LOCATOR_INVALID')
    if raw.get('kind') == 'JsonPointer':
        pointer = raw.get('pointer')
        if (set(raw) != {'kind', 'pointer'}
                or not isinstance(pointer, str) or len(pointer) > 250
                or pointer != '' and not pointer.startswith('/')
                or pointer.count('/') > 32
                or re.search(r'~(?![01])', pointer)):
            raise ValueError('POLICY_SOURCE_VALUE_LOCATOR_INVALID')
    elif raw.get('kind') == 'Utf8TextSpan':
        if (set(raw) != {'kind', 'start', 'end'}
                or type(raw['start']) is not int
                or type(raw['end']) is not int
                or not 0 <= raw['start'] < raw['end'] <= MAX_DOCUMENT_BYTES
                or raw['end'] - raw['start'] > 128):
            raise ValueError('POLICY_SOURCE_VALUE_LOCATOR_INVALID')
    elif raw.get('kind') == 'ClientPdfTextSpan':
        if (set(raw) != {'kind','pdfArtifactId','pdfContentSha256',
                         'extractionArtifactId','extractionSha256',
                         'page','pageTextSha256','extractionSchemaVersion',
                         'start','end','numberFormat'}
                or not isinstance(raw['pdfArtifactId'],str)
                or not re.fullmatch(r'[A-Za-z0-9._-]{8,128}',
                                    raw['pdfArtifactId'])
                or not isinstance(raw['pdfContentSha256'],str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                                    raw['pdfContentSha256'])
                or not isinstance(raw['extractionArtifactId'],str)
                or not re.fullmatch(r'[A-Za-z0-9._-]{8,128}',
                                    raw['extractionArtifactId'])
                or not isinstance(raw['extractionSha256'],str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                                    raw['extractionSha256'])
                or type(raw['page']) is not int or not 1 <= raw['page'] <= 100
                or not isinstance(raw['pageTextSha256'],str)
                or not re.fullmatch(r'[0-9a-f]{64}',raw['pageTextSha256'])
                or raw['extractionSchemaVersion'] != CLIENT_PDF_SCHEMA
                or type(raw['start']) is not int or type(raw['end']) is not int
                or not 0 <= raw['start'] < raw['end'] <= 200000
                or raw['end']-raw['start'] > 128
                or raw['numberFormat'] not in
                    ('PlainDecimal','CommaGroupedDecimal')):
            raise ValueError('POLICY_SOURCE_VALUE_LOCATOR_INVALID')
    else:
        raise ValueError('POLICY_SOURCE_VALUE_LOCATOR_INVALID')
    return dict(raw)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('POLICY_SOURCE_JSON_DUPLICATE_KEY')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('POLICY_SOURCE_JSON_INVALID')


class CapturedSourceValues:
    """Parse each hash-checked document once per evaluation, within budgets."""

    def __init__(self):
        self.documents = {}
        self.total_bytes = 0

    def verify(self, artifact: dict, locator: dict, expected: str) -> str:
        locator = validate_locator(locator)
        artifact_id = artifact['artifact_id']
        is_client_pdf = locator['kind'] == 'ClientPdfTextSpan'
        if is_client_pdf and (
                artifact['media_type'] != 'application/pdf'
                or artifact_id != locator['pdfArtifactId']
                or artifact['content_sha256'] !=
                    locator['pdfContentSha256']
                or artifact.get('client_extraction_id') !=
                    locator['extractionArtifactId']
                or artifact.get('client_extraction_sha256') !=
                    locator['extractionSha256']):
            raise ValueError('POLICY_SOURCE_CLIENT_PDF_DOCUMENT_MISMATCH')
        if artifact_id not in self.documents:
            content = bytes(artifact['client_extraction'] if is_client_pdf
                            else artifact['content'])
            digest = (artifact['client_extraction_sha256'] if is_client_pdf
                      else artifact['content_sha256'])
            limit = 2 * 1024 * 1024 if is_client_pdf else MAX_DOCUMENT_BYTES
            if (not 1 <= len(content) <= limit
                    or self.total_bytes + len(content) > MAX_TOTAL_BYTES):
                raise ValueError('POLICY_SOURCE_VALUE_DOCUMENT_BUDGET_EXCEEDED')
            if sha256(content).hexdigest() != digest:
                raise ValueError('POLICY_SOURCE_ARTIFACT_CORRUPT')
            if is_client_pdf:
                manifest = validate_manifest(content,
                    document_artifact_id=locator['pdfArtifactId'],
                    document_sha256=locator['pdfContentSha256'])
                document = {'client_pdf':manifest}
            else:
                try:
                    text = content.decode('utf-8', errors='strict')
                except UnicodeError as error:
                    raise ValueError('POLICY_SOURCE_VALUE_UTF8_INVALID') from error
                document = {'text':text}
            self.total_bytes += len(content)
            self.documents[artifact_id] = document
        document = self.documents[artifact_id]
        if locator['kind'] == 'ClientPdfTextSpan':
            page = locator['page']
            extracted = document['client_pdf']['pages'].get(page)
            if extracted is None:
                raise ValueError('POLICY_SOURCE_CLIENT_PDF_PAGE_UNAVAILABLE')
            if extracted['pageTextSha256'] != locator['pageTextSha256']:
                raise ValueError('POLICY_SOURCE_CLIENT_PDF_PAGE_TEXT_MISMATCH')
            if locator['end'] > len(extracted['pageText']):
                raise ValueError('POLICY_SOURCE_VALUE_LOCATION_UNAVAILABLE')
            value = extracted['pageText'][locator['start']:locator['end']]
            if locator['numberFormat'] == 'CommaGroupedDecimal':
                if not re.fullmatch(r'[-+]?[0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,8})?',value):
                    raise ValueError(
                        'POLICY_SOURCE_CLIENT_PDF_NUMBER_FORMAT_INVALID')
                value = value.replace(',','')
        elif locator['kind'] == 'Utf8TextSpan':
            if artifact['media_type'] != 'text/plain':
                raise ValueError('POLICY_SOURCE_VALUE_MEDIA_TYPE_UNSUPPORTED')
            if locator['end'] > len(document['text']):
                raise ValueError('POLICY_SOURCE_VALUE_LOCATION_UNAVAILABLE')
            value = document['text'][locator['start']:locator['end']]
        else:
            if artifact['media_type'] != 'application/json':
                raise ValueError('POLICY_SOURCE_VALUE_MEDIA_TYPE_UNSUPPORTED')
            if 'json' not in document:
                try:
                    value = json.loads(document['text'],
                        parse_int=Decimal, parse_float=Decimal,
                        parse_constant=_reject_constant,
                        object_pairs_hook=_unique_object)
                except (json.JSONDecodeError, RecursionError,
                        ArithmeticError) as error:
                    raise ValueError('POLICY_SOURCE_JSON_INVALID') from error
                pending = [(value, 0)]
                count = 0
                while pending:
                    node, depth = pending.pop()
                    count += 1
                    if count > 50000 or depth > 64:
                        raise ValueError('POLICY_SOURCE_JSON_BUDGET_EXCEEDED')
                    if isinstance(node, dict):
                        if count + len(pending) + len(node) > 50000:
                            raise ValueError('POLICY_SOURCE_JSON_BUDGET_EXCEEDED')
                        pending.extend((child, depth + 1)
                                       for child in node.values())
                    elif isinstance(node, list):
                        if count + len(pending) + len(node) > 50000:
                            raise ValueError('POLICY_SOURCE_JSON_BUDGET_EXCEEDED')
                        pending.extend((child, depth + 1) for child in node)
                document['json'] = value
            value = document['json']
            tokens = (locator['pointer'][1:].split('/')
                      if locator['pointer'] else [])
            for token in tokens:
                token = token.replace('~1', '/').replace('~0', '~')
                if isinstance(value, dict) and token in value:
                    value = value[token]
                elif (isinstance(value, list)
                      and re.fullmatch(r'0|[1-9][0-9]*', token)
                      and len(token) <= 7 and int(token) < len(value)):
                    value = value[int(token)]
                else:
                    raise ValueError('POLICY_SOURCE_VALUE_LOCATION_UNAVAILABLE')
        if not isinstance(value, (str, Decimal)):
            raise ValueError('POLICY_SOURCE_VALUE_NUMERIC_REQUIRED')
        try:
            amount = Decimal(value)
            NumericCell(True, amount, '')
        except (ArithmeticError, ValueError) as error:
            raise ValueError('POLICY_SOURCE_VALUE_NUMERIC_INVALID') from error
        if amount != Decimal(expected):
            raise ValueError('POLICY_SOURCE_VALUE_EXTRACTED_MISMATCH')
        return format(amount, '.8f')
