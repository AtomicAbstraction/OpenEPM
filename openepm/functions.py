"""Runtime-generated application functions from authenticated MCP discovery.

The SDK deliberately ships no static allow-list.  Each registry is generated
from one application's currently filtered server catalog, so a consolidation-
disabled application cannot manufacture a discoverable specialized wrapper.
The resulting Program is still validated authoritatively by the server.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Any,Iterator,Mapping

from .model import Program,_canonical_copy,_identifier


REGISTRY_FORMAT = 'openepm-function-registry-v1'
PROCESSING_REGISTRY_FORMAT = 'openepm-processing-operation-registry-v2'


def _registry_digest(functions: Mapping[str,Any]) -> str:
    envelope={'format':REGISTRY_FORMAT,'languageVersion':2,
              'functions':_canonical_copy(functions,label='functions')}
    return sha256(json.dumps(envelope,sort_keys=True,separators=(',',':'),
        ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()


@dataclass(frozen=True,slots=True)
class Function:
    name: str
    specification: Mapping[str,Any]
    operation_contract: Mapping[str,Any]|None = None

    def program(self,arguments: Mapping[str,Any],*,unit_name: str='unit') -> Program:
        """Construct a typed plan; this is convenience, not authorization."""
        return Program.one(self.name,arguments,name=unit_name)


class FunctionRegistry(Mapping[str,Function]):
    def __init__(self,catalog: Mapping[str,Any]):
        if (not isinstance(catalog,Mapping) or catalog.get('languageVersion')!=2
                or not isinstance(catalog.get('functions'),Mapping)):
            raise ValueError('OPEN_EPM_DISCOVERY_INVALID')
        registry_format=catalog.get('registryFormat')
        registry_digest=catalog.get('registryDigest')
        if ((registry_format is None) != (registry_digest is None)
                or registry_format is not None and (
                    registry_format != REGISTRY_FORMAT
                    or not isinstance(registry_digest,str)
                    or registry_digest != _registry_digest(catalog['functions']))):
            raise ValueError('OPEN_EPM_DISCOVERY_REGISTRY_MISMATCH')
        generated={}
        contracts=catalog.get('operationContracts')
        processing_format=catalog.get('processingRegistryFormat')
        if ((contracts is None)!=(processing_format is None)
                or contracts is not None and (
                    processing_format!=PROCESSING_REGISTRY_FORMAT
                    or not isinstance(contracts,Mapping)
                    or set(contracts)!=set(catalog['functions']))):
            raise ValueError('OPEN_EPM_DISCOVERY_PROCESSING_REGISTRY_MISMATCH')
        for name,specification in catalog['functions'].items():
            _identifier(name,'function')
            copied=_canonical_copy(specification,label='function specification')
            if not isinstance(copied,dict):
                raise ValueError('OPEN_EPM_DISCOVERY_INVALID')
            contract=None
            if contracts is not None:
                contract_copy=_canonical_copy(
                    contracts[name],label='operation contract')
                if (not isinstance(contract_copy,dict)
                        or contract_copy.get('function')!=name
                        or any(contract_copy.get(field)!=copied.get(field)
                               for field in ('permission','previewRequired',
                                             'idempotencyRequired','workClass'))):
                    raise ValueError(
                        'OPEN_EPM_DISCOVERY_PROCESSING_REGISTRY_MISMATCH')
                contract=MappingProxyType(contract_copy)
            generated[name]=Function(name,MappingProxyType(copied),contract)
        self._functions=MappingProxyType(generated)
        self.enabled_capabilities=tuple(catalog.get('enabledCapabilities',()))
        self.capability_revision=catalog.get('capabilityRevision')
        self.registry_format=registry_format
        self.registry_digest=registry_digest
        self.processing_registry_format=processing_format

    def __getitem__(self,name: str) -> Function:return self._functions[name]
    def __iter__(self) -> Iterator[str]:return iter(self._functions)
    def __len__(self) -> int:return len(self._functions)

    def program(self,function: str,arguments: Mapping[str,Any],*,
                unit_name: str='unit') -> Program:
        try:entry=self._functions[function]
        except KeyError:raise ValueError('FUNCTION_NOT_DISCOVERED') from None
        return entry.program(arguments,unit_name=unit_name)


def generate_function_registry(catalog: Mapping[str,Any]) -> FunctionRegistry:
    """Public generator entry point used by SDK and parity tests."""
    return FunctionRegistry(catalog)
