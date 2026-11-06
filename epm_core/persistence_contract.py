"""Backend-neutral identities and mutation semantics for the EPM fact core.

Storage adapters preserve these contracts across the application language,
transactional store and calculation stages.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from enum import StrEnum
from hashlib import sha256
import json
from typing import Protocol, Sequence


AMOUNT_INTEGER_DIGITS = 20
AMOUNT_SCALE = 8


def _validate_amount(amount: Decimal) -> None:
    if not isinstance(amount, Decimal) or not amount.is_finite():
        raise ValueError('Numeric amount must be a finite Decimal')
    digits = len(amount.as_tuple().digits)
    exponent = amount.as_tuple().exponent
    if max(0, digits + exponent) > AMOUNT_INTEGER_DIGITS or -exponent > AMOUNT_SCALE:
        raise ValueError('Numeric amount exceeds NUMERIC(28,8)')


@dataclass(frozen=True, slots=True)
class ApplicationScope:
    workspace_id: str
    application_id: str

    def __post_init__(self) -> None:
        if (not isinstance(self.workspace_id, str) or not self.workspace_id or
                not isinstance(self.application_id, str) or not self.application_id):
            raise ValueError('Workspace and application IDs are required')


@dataclass(frozen=True, slots=True)
class Coordinate:
    """An exact point in a generic cube, independent of finance-specific axes."""

    members: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, members: dict[str, str]) -> Coordinate:
        if not isinstance(members, dict) or not members:
            raise ValueError('Coordinate needs at least one dimension/member pair')
        if any(not isinstance(dimension, str) or not dimension or
               not isinstance(member, str) or not member
               for dimension, member in members.items()):
            raise ValueError('Coordinate IDs must be nonempty strings')
        return cls(tuple(sorted(members.items())))

    def __post_init__(self) -> None:
        if not self.members or tuple(sorted(self.members)) != self.members:
            raise ValueError('Coordinate members must be canonical and nonempty')
        dimensions = [dimension for dimension, _ in self.members]
        if len(dimensions) != len(set(dimensions)) or any(
                not isinstance(dimension, str) or not dimension or
                not isinstance(member, str) or not member
                for dimension, member in self.members):
            raise ValueError('Coordinate needs one member per dimension')

    @property
    def series_key(self) -> str:
        """Keep the existing public key for newly authored coordinates."""
        canonical = json.dumps(self.members, ensure_ascii=False,
                               separators=(',', ':')).encode()
        return sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class NumericCell:
    """Presence is independent of amount; present zero differs from missing."""

    present: bool
    amount: Decimal | None
    change_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.present, bool):
            raise ValueError('Presence must be a boolean')
        if self.present != (self.amount is not None):
            raise ValueError('Present cells need an amount; missing cells do not')
        if self.amount is not None:
            _validate_amount(self.amount)

    @classmethod
    def from_wire(cls, *, present: bool, amount: str | None,
                  change_id: str = '') -> NumericCell:
        if amount is not None and not isinstance(amount, str):
            raise ValueError('Numeric amounts cross the boundary as decimal strings')
        try:
            parsed = Decimal(amount) if amount is not None else None
        except (ArithmeticError, ValueError) as error:
            raise ValueError('Numeric amount is not a decimal string') from error
        return cls(present, parsed, change_id)

    def wire_amount(self) -> str | None:
        return format(self.amount, 'f') if self.amount is not None else None


class MutationKind(StrEnum):
    SET = 'set'
    ADD = 'add'
    CLEAR = 'clear'


@dataclass(frozen=True, slots=True)
class NumericMutation:
    coordinate: Coordinate
    kind: MutationKind
    amount: Decimal | None
    expected_change_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, MutationKind):
            raise ValueError('Unknown numeric mutation kind')
        if self.kind == MutationKind.CLEAR:
            if self.amount is not None:
                raise ValueError('Clear does not take an amount')
        else:
            _validate_amount(self.amount)


@dataclass(frozen=True, slots=True)
class MutationReceipt:
    operation_id: str
    committed_revision: int
    changed_count: int


class NumericFactStore(Protocol):
    """An adapter commits mutation effects, revision and receipt atomically."""

    def read_current(self, scope: ApplicationScope, coordinate: Coordinate,
                     *, snapshot_revision: int | None = None) -> NumericCell: ...

    def apply(self, scope: ApplicationScope, mutations: Sequence[NumericMutation],
              *, operation_id: str, command_digest: str, actor_id: str,
              expected_metadata_revision: int,
              expected_data_revision: int | None = None) -> MutationReceipt: ...


class TextMutationKind(StrEnum):
    SET = 'set'
    CLEAR = 'clear'


@dataclass(frozen=True, slots=True)
class TextCell:
    present: bool
    value: str | None
    change_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.present, bool) or self.present != (self.value is not None):
            raise ValueError('Text presence and value disagree')
        if self.value is not None and (not isinstance(self.value, str) or
                                       len(self.value) > 32768 or '\x00' in self.value):
            raise ValueError('Text value must be at most 32768 characters without NUL')


@dataclass(frozen=True, slots=True)
class TextMutation:
    coordinate: Coordinate
    kind: TextMutationKind
    value: str | None
    expected_change_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.coordinate, Coordinate) or not isinstance(
                self.kind, TextMutationKind):
            raise ValueError('A text mutation needs a coordinate and kind')
        TextCell(self.kind == TextMutationKind.SET, self.value,
                 self.expected_change_id)


class TextFactStore(Protocol):
    def read_current(self, scope: ApplicationScope, coordinate: Coordinate,
                     *, snapshot_revision: int | None = None) -> TextCell: ...

    def apply(self, scope: ApplicationScope, mutations: Sequence[TextMutation],
              *, operation_id: str, command_digest: str, actor_id: str,
              expected_metadata_revision: int,
              expected_data_revision: int | None = None) -> MutationReceipt: ...


@dataclass(frozen=True, slots=True)
class LineItem:
    description: str
    amount: Decimal

    def __post_init__(self) -> None:
        if (not isinstance(self.description, str)
                or not 1 <= len(self.description) <= 80
                or '\x00' in self.description):
            raise ValueError('Line item description must be 1–80 characters without NUL')
        _validate_amount(self.amount)


@dataclass(frozen=True, slots=True)
class LineDetailCell:
    present: bool
    items: tuple[LineItem, ...]
    total: Decimal | None
    change_id: str

    def __post_init__(self) -> None:
        if (not isinstance(self.present, bool)
                or not isinstance(self.items, tuple)
                or len(self.items) > 500
                or any(not isinstance(item, LineItem) for item in self.items)
                or self.present != (self.total is not None)
                or (not self.present and self.items)):
            raise ValueError('Line detail presence, items and total disagree')
        if self.total is not None:
            _validate_amount(self.total)
            with localcontext() as context:
                context.prec = 64
                if sum((item.amount for item in self.items), Decimal(0)) != self.total:
                    raise ValueError('Line detail total does not match its items')


class LineDetailStore(Protocol):
    def read_current(self, scope: ApplicationScope, coordinate: Coordinate,
                     *, snapshot_revision: int | None = None) -> LineDetailCell: ...

    def apply(self, scope: ApplicationScope, coordinate: Coordinate,
              items: tuple[LineItem, ...], *, operation_id: str,
              command_digest: str, actor_id: str,
              expected_metadata_revision: int,
              expected_cell_change_id: str,
              expected_detail_change_id: str,
              expected_data_revision: int | None = None) -> MutationReceipt: ...
