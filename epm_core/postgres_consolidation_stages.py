"""Pure accounting-stage identities shared by compilers and dependency reads."""

ACQUISITION_LAYERS=frozenset((
    'raw_plus_acquisition_journal',
    'raw_plus_manual_journal_plus_acquisition_journal',
    'raw_plus_ic_elimination_plus_acquisition_journal',
    'raw_plus_manual_journal_plus_ic_elimination_plus_acquisition_journal'))
ACQUISITION_LOCAL_STAGES={
    'raw_plus_acquisition_journal':'local_full_acquisition_adjusted',
    'raw_plus_manual_journal_plus_acquisition_journal':'local_full_journal_acquisition_adjusted',
    'raw_plus_ic_elimination_plus_acquisition_journal':'local_full_ic_acquisition_adjusted',
    'raw_plus_manual_journal_plus_ic_elimination_plus_acquisition_journal':'local_full_journal_ic_acquisition_adjusted'}

ACQUISITION_TRANSLATED_STAGES={
    layer:stage.replace('local_full_','translated_full_')
    for layer,stage in ACQUISITION_LOCAL_STAGES.items()}
BASE_TRANSLATED_STAGES={
    'translated_full':'pre_nci_translated_uneliminated',
    'raw_plus_ic_elimination':'pre_nci_translated_ic_adjusted',
    'raw_plus_manual_journal_plus_ic_elimination':'pre_nci_translated_journal_ic_adjusted'}
TRANSLATED_STAGES={**BASE_TRANSLATED_STAGES,**ACQUISITION_TRANSLATED_STAGES}

ACQUISITION_OWN_STAGES={layer:stage.replace("local_full_","translated_own_")
    for layer,stage in ACQUISITION_LOCAL_STAGES.items()}
