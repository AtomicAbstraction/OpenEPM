"""Safe repair guidance from fixed public contracts, never caller values."""
from __future__ import annotations

from functools import lru_cache

from jsonschema import Draft202012Validator, validators
from referencing import Registry

from openepm.public_diagnostics import (
    PROGRAM_CODE as CODE, PROGRAM_FORMAT as FORMAT, STRUCTURAL_BOUNDS,
    STRUCTURAL_EXPECTATIONS, STRUCTURAL_RECOVERY, program_diagnostic as diagnostic_payload)


def validate_program_diagnostic(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError('PROGRAM_DIAGNOSTIC_INVALID')
    canonical = (structural_diagnostic_payload(value.get('function'),
        value.get('path'), value.get('keyword'))
        if value.get('violation') == 'structure'
        else diagnostic_payload(value.get('violation')))
    if value != canonical:
        raise ValueError('PROGRAM_DIAGNOSTIC_INVALID')
    return canonical


class ProgramValidationError(ValueError):
    code = CODE

    def __init__(self, violation: str, *, function: str | None = None,
                 path: str | None = None, keyword: str | None = None):
        self.diagnostics = (structural_diagnostic_payload(function, path, keyword)
            if violation == 'structure' else diagnostic_payload(violation))
        super().__init__(self.code)


# JSON Schema considers 2.0 an integer. Fixed Python owners deliberately accept
# only actual JSON integer values, and never bools, for revisions and limits.
_Validator = validators.extend(Draft202012Validator,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
        'integer', lambda _checker, instance: type(instance) is int))


def _local_schema_reference(schema, reference):
    """Resolve only fixed local JSON pointers; never fetch a schema URI."""
    if not isinstance(reference, str) or not (reference == '#' or reference.startswith('#/')):
        raise ValueError('PUBLIC_PROGRAM_SCHEMA_REFERENCE_INVALID')
    target = schema
    for part in reference[2:].split('/') if reference != '#' else ():
        # Current owners use plain JSON-pointer fragments, not URI/anchor aliases.
        if '%' in part or any(not piece or piece[0] not in '01' for piece in part.split('~')[1:]):
            raise ValueError('PUBLIC_PROGRAM_SCHEMA_REFERENCE_INVALID')
        part = part.replace('~1', '/').replace('~0', '~')
        if not isinstance(target, dict) or part not in target:
            raise ValueError('PUBLIC_PROGRAM_SCHEMA_REFERENCE_INVALID')
        target = target[part]
    if not isinstance(target, (dict, bool)):
        raise ValueError('PUBLIC_PROGRAM_SCHEMA_REFERENCE_INVALID')
    return target


def _schema_diagnostic_options(schema):
    """Bounded fixed-path hints, not another schema validator or grammar."""
    # Audit references even in dynamic maps, which must not contribute caller
    # keys to diagnostics. Literal defaults/examples/const values are data.
    pending, seen = [(schema, 0)], set()
    while pending:
        node, depth = pending.pop()
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        if len(seen) > 4096 or depth > 64:
            raise ValueError('PUBLIC_PROGRAM_SCHEMA_TRAVERSAL_LIMIT')
        if '$ref' in node:
            _local_schema_reference(schema, node['$ref'])
        for keyword in ('$defs', 'definitions', 'properties', 'patternProperties', 'dependentSchemas'):
            pending.extend((child, depth + 1) for child in node.get(keyword, {}).values())
        for keyword in ('allOf', 'anyOf', 'oneOf', 'prefixItems'):
            pending.extend((child, depth + 1) for child in node.get(keyword, []))
        for keyword in ('items', 'additionalItems', 'additionalProperties', 'unevaluatedProperties',
                        'unevaluatedItems', 'propertyNames', 'contains', 'if', 'then', 'else', 'not'):
            pending.append((node.get(keyword), depth + 1))

    generic = STRUCTURAL_EXPECTATIONS['contract']
    visits = 0
    required_paths = set()

    def merge(maps, *, alternatives=False):
        result = {}
        for path in sorted({path for mapping in maps for path in mapping}):
            choices = {'contract': {generic}}
            for keyword in {key for mapping in maps for key in mapping.get(path, {})} - {'contract'}:
                # Missing or different alternative claims stay ambiguous. A
                # union must not advertise one branch's type or tighter bound.
                values = set()
                for mapping in maps:
                    values.update(mapping.get(path, {}).get(keyword, {None} if alternatives else set()))
                choices[keyword] = values
            result[path] = choices
        return result

    def visit(node, path, required=False, references=frozenset(), depth=0):
        nonlocal visits
        visits += 1
        if visits > 4096 or depth > 64:
            raise ValueError('PUBLIC_PROGRAM_SCHEMA_TRAVERSAL_LIMIT')
        choices = {'contract': {generic}}
        if required:
            choices['required'] = {STRUCTURAL_EXPECTATIONS['required']}
        if not isinstance(node, dict):
            return {path: choices}
        types = node.get('type')
        expected = ' or '.join(sorted(types)) if isinstance(types, list) else types
        if isinstance(expected, str):
            choices['type'] = {expected}
        if node.get('additionalProperties') is False:
            choices['additionalProperties'] = {STRUCTURAL_EXPECTATIONS['additionalProperties']}
        for keyword, label in STRUCTURAL_BOUNDS.items():
            if type(node.get(keyword)) is int:
                choices[keyword] = {f'{label} {node[keyword]}'}
        for keyword in ('const', 'enum', 'pattern', 'anyOf', 'oneOf'):
            if keyword in node:
                choices[keyword] = {STRUCTURAL_EXPECTATIONS[keyword]}
        parts = [{path: choices}]
        if '$ref' in node:
            reference = node['$ref']
            target = _local_schema_reference(schema, reference)
            if reference not in references:
                parts.append(visit(target, path, required, references | {reference}, depth + 1))
        required_fields = node.get('required', [])
        for name in required_fields:
            if not isinstance(name, str) or not name.isidentifier():
                raise ValueError('PUBLIC_PROGRAM_SCHEMA_PATH_INVALID')
            required_paths.add(path + '.' + name)
        for name, child in node.get('properties', {}).items():
            if not isinstance(name, str) or not name.isidentifier():
                raise ValueError('PUBLIC_PROGRAM_SCHEMA_PATH_INVALID')
            parts.append(visit(child, path + '.' + name, name in required_fields, references, depth + 1))
        if isinstance(node.get('items'), (dict, bool)):
            parts.append(visit(node['items'], path + '[*]', False, references, depth + 1))
        for branch in node.get('allOf', []):
            parts.append(visit(branch, path, required, references, depth + 1))
        for keyword in ('anyOf', 'oneOf'):
            if node.get(keyword):
                parts.append(merge([visit(branch, path, required, references, depth + 1)
                    for branch in node[keyword]], alternatives=True))
        if 'then' in node or 'else' in node:
            parts.append(merge([visit(node.get(keyword, {}), path, required, references, depth + 1)
                for keyword in ('then', 'else')], alternatives=True))
        return merge(parts)

    collected = visit(schema, '$')
    options = {path: {key: next(iter(values)) for key, values in choices.items()
                      if len(values) == 1 and None not in values}
               for path, choices in collected.items()}
    # A conditional/allOf may require a property declared alongside it. Keep
    # its fixed name; only the real validator decides whether it is required.
    for path in required_paths & options.keys():
        options[path]['required'] = STRUCTURAL_EXPECTATIONS['required']
    return options


@lru_cache(maxsize=16)
def _structural_contract(function: str):
    # This lookup admits only owner-qualified, parser-parity-tested
    # contracts. Other published schemas can describe partial discriminants;
    # they must not silently become new runtime validators.
    from .public_program_contracts import public_program_contract
    contract = public_program_contract(function)
    if contract is None:
        return None
    schema = contract['programSchema']
    options = _schema_diagnostic_options(schema)
    # Supplying an empty registry also disables implicit remote retrieval in
    # validation paths (including dynamic maps that do not expose child hints).
    return _Validator(schema, registry=Registry()), options


def structural_diagnostic_payload(function: object, path: object, keyword: object) -> dict:
    if not isinstance(function, str) or not isinstance(path, str) or not isinstance(keyword, str):
        raise ValueError('PROGRAM_DIAGNOSTIC_INVALID')
    contract = _structural_contract(function)
    if contract is None or path not in contract[1] or keyword not in contract[1][path]:
        raise ValueError('PROGRAM_DIAGNOSTIC_INVALID')
    return {'format': FORMAT, 'violation': 'structure', 'function': function,
            'path': path, 'keyword': keyword, 'expected': contract[1][path][keyword],
            'recovery': STRUCTURAL_RECOVERY.get(keyword, STRUCTURAL_RECOVERY['contract'])}


def validate_program_structure(program: dict, *, scope: str = 'application') -> None:
    """Check the explicit qualified subset; native semantics/authority still run."""
    from .public_program_contracts import public_program_contract_scope

    if public_program_contract_scope(program['function']) != scope:
        return
    contract = _structural_contract(program['function'])
    if contract is None:
        return
    validator, options = contract
    error = next(validator.iter_errors(program), None)
    if error is None:
        return
    path = '$'
    exact_path = True
    instance = program
    for part in error.absolute_path:
        candidate = path + ('[*]' if isinstance(part, int) else '.' + str(part))
        if candidate not in options:
            exact_path = False
            break
        path = candidate
        instance = instance[part]
    # A child error cannot reuse the ancestor's type/bound as its explanation.
    # propertyNames errors also carry the map's path but describe a key value.
    keyword = error.validator if exact_path and error.instance is instance else 'contract'
    if keyword == 'required' and isinstance(error.instance, dict):
        for field in error.validator_value:
            candidate = path + '.' + field
            if field not in error.instance and 'required' in options.get(candidate, {}):
                path = candidate
                break
    if keyword not in options[path]:
        keyword = 'contract'
    raise ProgramValidationError('structure', function=program['function'],
                                 path=path, keyword=keyword)


def validate_program_envelope(program: object, *, scope: str = 'application') -> None:
    if type(program) is not dict:
        raise ProgramValidationError('object')
    # Missing known fields get a useful path, without repeating unknown keys.
    if type(program.get('languageVersion')) is not int or program['languageVersion'] != 2:
        violation = f'{scope}_version' if scope in ('workspace', 'platform') else 'version'
        raise ProgramValidationError(violation)
    if type(program.get('function')) is not str or not program['function']:
        raise ProgramValidationError('function')
    if type(program.get('arguments')) is not dict:
        raise ProgramValidationError('arguments')
    if set(program) != {'languageVersion', 'function', 'arguments'}:
        raise ProgramValidationError('fields')
