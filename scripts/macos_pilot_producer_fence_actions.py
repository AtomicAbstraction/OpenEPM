#!/usr/bin/env python3
"""Fixed privileged actions for the all-producer fence."""
from __future__ import annotations

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts.macos_pilot_all_producer_fence import AllProducerFence,ProducerFenceError

def apply_close_all_producers(fence:AllProducerFence,*,operation_key:str,
 contract:dict,journal_head:str,journal_generation:int,
 observed_at_utc:str)->dict:
 return fence.close(operation_key=operation_key,contract=contract,
  journal_head=journal_head,journal_generation=journal_generation,
  observed_at_utc=observed_at_utc)

def observe_close_all_producers(fence:AllProducerFence,manifest:dict,
 *,operation_key:str,contract:dict)->dict|None:
 if manifest.get('intentEventSha256')!=operation_key \
    or manifest.get('activationId')!=contract.get('activationId') \
    or manifest.get('executionContractSha256')!=contract.get(
     'executionContractSha256'):
  raise ProducerFenceError('producer fence manifest differs')
 if fence.boundary.producers_stopped() is not True \
    or fence.boundary.producer_sessions_zero() is not True \
    or any(fence.observer.observe().values()):
  return None
 return manifest

def apply_reopen_selected_slot(fence:AllProducerFence,provider,*,kind:str,
 slot:str,manifest:dict,operation_key:str,contract:dict,
 start_services:bool=True)->str:
 # Authority is always read by the protected provider.  Neither the caller nor
 # this helper accepts key material, a proof path, or an authority object.
 authority=provider.authority(kind,slot,manifest,contract)
 if authority.get('operationKey',operation_key)!=operation_key:
  raise ProducerFenceError('producer reopen operation differs')
 method=fence.reopen if start_services else fence.reopen_modes
 return method(manifest,operation_key=operation_key,contract=contract,
               authority=authority)
