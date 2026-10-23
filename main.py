"""Compile Alvara trait settings into deterministic contract memory artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
COMBINATION_CURSOR_DELTA = 99_133
MAX_TRAIT_SEARCH_ATTEMPTS = 128
MAX_TRAVERSAL_VALIDATION_STATES = 1_000_000


class ValidationError(ValueError):
    """Raised when settings cannot be represented by the trait layout."""


@dataclass(frozen=True)
class BitField:
    name: str
    width: int


@dataclass(frozen=True)
class TraitLayout:
    """Single source of truth for the on-chain bit layout."""

    option_bits: int = 5
    attribute_count: int = 7
    category_range_bits: int = 13
    total_size_bits: int = 16
    max_stream_bits: int = 16
    category_fields: tuple[BitField, ...] = (
        BitField("name_shift", 16),
        BitField("name_size", 4),
        BitField("attr_start", 8),
        BitField("attr_count", 3),
        BitField("ignored_start", 8),
        BitField("ignored_size", 4),
        BitField("included_start", 8),
        BitField("included_size", 4),
        BitField("space_size", 32),
    )
    attribute_fields: tuple[BitField, ...] = (
        BitField("name_shift", 16),
        BitField("name_size", 4),
        BitField("place_multiplier", 16),
    )

    @property
    def category_entry_bits(self) -> int:
        return sum(field.width for field in self.category_fields)

    @property
    def attribute_entry_bits(self) -> int:
        return sum(field.width for field in self.attribute_fields)

    @property
    def option_vector_bits(self) -> int:
        return self.option_bits * self.attribute_count

    @property
    def ignore_entry_bits(self) -> int:
        return self.option_vector_bits * 2

    @property
    def include_entry_bits(self) -> int:
        return self.option_vector_bits


LAYOUT = TraitLayout()


@dataclass(frozen=True)
class CategorySpec:
    name: str
    size: int
    attribute_names: tuple[str, ...]
    option_counts: tuple[int, ...]
    ignored: tuple[tuple[int, int, int, int], ...]
    included: tuple[tuple[int, ...], ...]
    space_size: int
    ignored_space_size: int

    @property
    def normal_size(self) -> int:
        return self.size - len(self.included)


@dataclass(frozen=True)
class CompiledMemory:
    names: str
    bit_string: str
    words: tuple[int, ...]
    register: Mapping[str, int]
    categories_sha256: str
    words_sha256: str
    total_size: int
    category_count: int
    max_rejection_run: int

    @property
    def bit_length(self) -> int:
        return len(self.bit_string)


def _max_uint(width: int) -> int:
    return (1 << width) - 1


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{path} must be an object")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"{path} must be an array")
    return value


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{path} must be a non-empty string")
    return value


def _require_int(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{path} must be an integer")
    if value < minimum:
        raise ValidationError(f"{path} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{path} must be at most {maximum}")
    return value


def _encode_uint(value: int, width: int, path: str) -> str:
    _require_int(value, path, maximum=_max_uint(width))
    return format(value, f"0{width}b")


def _field_offsets(fields: Sequence[BitField]) -> dict[str, int]:
    result: dict[str, int] = {}
    offset = 0
    for field in fields:
        result[field.name] = offset
        offset += field.width
    return result


def _pack_named_fields(
    values: Mapping[str, int], fields: Sequence[BitField], path: str
) -> str:
    return "".join(
        _encode_uint(values[field.name], field.width, f"{path}.{field.name}")
        for field in fields
    )


def _pack_option_vector(options: Sequence[int], path: str) -> str:
    if len(options) != LAYOUT.attribute_count:
        raise ValidationError(
            f"{path} must contain exactly {LAYOUT.attribute_count} option indexes"
        )
    return "".join(
        _encode_uint(option, LAYOUT.option_bits, f"{path}[{index}]")
        for index, option in enumerate(options)
    )


def _validate_option(option: Any, path: str) -> None:
    item = _require_mapping(option, path)
    _require_string(item.get("name"), f"{path}.name")
    pictures = _require_list(item.get("pics"), f"{path}.pics")
    if not pictures:
        raise ValidationError(f"{path}.pics must not be empty")

    seen_pictures: set[tuple[str, int]] = set()
    for picture_index, picture in enumerate(pictures):
        picture_path = f"{path}.pics[{picture_index}]"
        picture_data = _require_mapping(picture, picture_path)
        file_path = _require_string(picture_data.get("path"), f"{picture_path}.path")
        z_index = _require_int(
            picture_data.get("z"),
            f"{picture_path}.z",
            minimum=-(1 << 31),
            maximum=(1 << 31) - 1,
        )
        identity = (file_path, z_index)
        if identity in seen_pictures:
            raise ValidationError(f"{picture_path} duplicates another picture")
        seen_pictures.add(identity)


def _matches_ignored(options: Sequence[int], rule: Sequence[int]) -> bool:
    pos0, option0, pos1, option1 = rule
    return options[pos0] == option0 and options[pos1] == option1


def _decode_options(number: int, option_counts: Sequence[int]) -> tuple[int, ...]:
    """Mirror the contract's mixed-radix option decoder."""

    reversed_options: list[int] = []
    for option_count in reversed(option_counts):
        reversed_options.append(number % option_count)
        number //= option_count
    return tuple(reversed(reversed_options))


def _maximum_rejection_run(spec: CategorySpec) -> int:
    """Prove the fixed cursor cannot encounter 128 consecutive rejected options."""

    if spec.normal_size == 0:
        return 0
    if spec.space_size > MAX_TRAVERSAL_VALIDATION_STATES:
        raise ValidationError(
            f"category {spec.name!r} has {spec.space_size} combinations; "
            "the fixed consumer traversal cannot be exhaustively validated"
        )
    if math.gcd(COMBINATION_CURSOR_DELTA, spec.space_size) != 1:
        raise ValidationError(
            f"category {spec.name!r} combination space is not coprime with the fixed cursor delta"
        )
    if spec.included and math.gcd(COMBINATION_CURSOR_DELTA, len(spec.included)) != 1:
        raise ValidationError(
            f"category {spec.name!r} included table is not coprime with the fixed cursor delta"
        )

    included = set(spec.included)
    rejected: list[bool] = []
    cursor = 0
    for _ in range(spec.space_size):
        cursor = (cursor + COMBINATION_CURSOR_DELTA) % spec.space_size
        options = _decode_options(cursor, spec.option_counts)
        rejected.append(
            options in included or any(_matches_ignored(options, rule) for rule in spec.ignored)
        )

    longest = 0
    current = 0
    for is_rejected in rejected + rejected:
        current = current + 1 if is_rejected else 0
        longest = max(longest, current)
    return min(longest, spec.space_size)


def _count_ignored_space(
    option_counts: Sequence[int], rules: Sequence[Sequence[int]]
) -> int:
    """Count the union of pair constraints without enumerating the trait space."""

    union_size = 0
    for subset in range(1, 1 << len(rules)):
        constraints: dict[int, int] = {}
        consistent = True
        selected = 0
        for rule_index, rule in enumerate(rules):
            if subset & (1 << rule_index) == 0:
                continue
            selected += 1
            for position, option in ((rule[0], rule[1]), (rule[2], rule[3])):
                existing = constraints.get(position)
                if existing is not None and existing != option:
                    consistent = False
                    break
                constraints[position] = option
            if not consistent:
                break

        intersection_size = 0
        if consistent:
            intersection_size = math.prod(
                count
                for position, count in enumerate(option_counts)
                if position not in constraints
            )
        union_size += intersection_size if selected % 2 else -intersection_size
    return union_size


def _validate_settings(settings: Any) -> tuple[tuple[CategorySpec, ...], bytes]:
    root = _require_mapping(settings, "settings")
    categories_data = _require_list(root.get("categories"), "settings.categories")
    if not categories_data:
        raise ValidationError("settings.categories must not be empty")

    specs: list[CategorySpec] = []
    seen_category_names: set[str] = set()
    name_offsets: dict[str, tuple[int, int]] = {}
    names = bytearray()
    total_attributes = 0
    total_ignored = 0
    total_included = 0

    def register_name(name: str, path: str) -> None:
        if name in name_offsets:
            return
        encoded = name.encode("utf-8")
        if len(encoded) > _max_uint(4):
            raise ValidationError(f"{path} exceeds the 4-bit UTF-8 name length")
        if len(names) + len(encoded) > 1 << 16:
            raise ValidationError(f"{path} exceeds the 16-bit name table range")
        name_offsets[name] = (len(names), len(encoded))
        names.extend(encoded)

    for category_index, category in enumerate(categories_data):
        category_path = f"settings.categories[{category_index}]"
        item = _require_mapping(category, category_path)
        name = _require_string(item.get("name"), f"{category_path}.name")
        if name in seen_category_names:
            raise ValidationError(f"{category_path}.name duplicates category {name!r}")
        seen_category_names.add(name)
        register_name(name, f"{category_path}.name")

        size = _require_int(item.get("size"), f"{category_path}.size", minimum=1)
        attributes = _require_list(item.get("attributes"), f"{category_path}.attributes")
        if len(attributes) != LAYOUT.attribute_count:
            raise ValidationError(
                f"{category_path}.attributes must contain exactly "
                f"{LAYOUT.attribute_count} attributes"
            )
        if total_attributes > _max_uint(8):
            raise ValidationError(f"{category_path} attribute start exceeds 8 bits")

        attribute_names: list[str] = []
        option_counts: list[int] = []
        seen_attribute_names: set[str] = set()
        for attribute_index, attribute in enumerate(attributes):
            attribute_path = f"{category_path}.attributes[{attribute_index}]"
            attribute_data = _require_mapping(attribute, attribute_path)
            attribute_name = _require_string(
                attribute_data.get("name"), f"{attribute_path}.name"
            )
            if attribute_name in seen_attribute_names:
                raise ValidationError(
                    f"{attribute_path}.name duplicates attribute {attribute_name!r}"
                )
            seen_attribute_names.add(attribute_name)
            register_name(attribute_name, f"{attribute_path}.name")
            attribute_names.append(attribute_name)

            options = _require_list(attribute_data.get("options"), f"{attribute_path}.options")
            if not options:
                raise ValidationError(f"{attribute_path}.options must not be empty")
            if len(options) > 1 << LAYOUT.option_bits:
                raise ValidationError(
                    f"{attribute_path}.options exceeds the {LAYOUT.option_bits}-bit option field"
                )

            seen_option_names: set[str] = set()
            for option_index, option in enumerate(options):
                option_path = f"{attribute_path}.options[{option_index}]"
                _validate_option(option, option_path)
                option_name = option["name"]
                if option_name in seen_option_names:
                    raise ValidationError(
                        f"{option_path}.name duplicates option {option_name!r}"
                    )
                seen_option_names.add(option_name)
            option_counts.append(len(options))

        total_attributes += len(attributes)
        if total_attributes > 1 << 8:
            raise ValidationError("total attribute entries exceed the 8-bit start field")

        ignored_data = _require_list(item.get("ignored"), f"{category_path}.ignored")
        if len(ignored_data) > _max_uint(4):
            raise ValidationError(f"{category_path}.ignored exceeds the 4-bit count field")
        if total_ignored > _max_uint(8):
            raise ValidationError(f"{category_path} ignored start exceeds 8 bits")
        ignored: list[tuple[int, int, int, int]] = []
        seen_ignored: set[tuple[tuple[int, int], tuple[int, int]]] = set()
        for ignored_index, rule in enumerate(ignored_data):
            rule_path = f"{category_path}.ignored[{ignored_index}]"
            values = _require_list(rule, rule_path)
            if len(values) != 4:
                raise ValidationError(
                    f"{rule_path} must be [attribute, option, attribute, option]"
                )
            pos0 = _require_int(
                values[0], f"{rule_path}[0]", maximum=LAYOUT.attribute_count - 1
            )
            option0 = _require_int(
                values[1], f"{rule_path}[1]", maximum=option_counts[pos0] - 1
            )
            pos1 = _require_int(
                values[2], f"{rule_path}[2]", maximum=LAYOUT.attribute_count - 1
            )
            option1 = _require_int(
                values[3], f"{rule_path}[3]", maximum=option_counts[pos1] - 1
            )
            if pos0 == pos1:
                raise ValidationError(f"{rule_path} must reference two distinct attributes")
            normalized = tuple(sorted(((pos0, option0), (pos1, option1))))
            if normalized in seen_ignored:
                raise ValidationError(f"{rule_path} duplicates another ignored rule")
            seen_ignored.add(normalized)
            ignored.append((pos0, option0, pos1, option1))
        total_ignored += len(ignored)
        if total_ignored > 1 << 8:
            raise ValidationError("total ignored entries exceed the 8-bit start field")

        included_data = _require_list(item.get("included"), f"{category_path}.included")
        if len(included_data) > _max_uint(4):
            raise ValidationError(f"{category_path}.included exceeds the 4-bit count field")
        if total_included > _max_uint(8):
            raise ValidationError(f"{category_path} included start exceeds 8 bits")
        included: list[tuple[int, ...]] = []
        seen_included: set[tuple[int, ...]] = set()
        for included_index, vector in enumerate(included_data):
            vector_path = f"{category_path}.included[{included_index}]"
            values = _require_list(vector, vector_path)
            if len(values) != LAYOUT.attribute_count:
                raise ValidationError(
                    f"{vector_path} must contain exactly {LAYOUT.attribute_count} indexes"
                )
            checked = tuple(
                _require_int(
                    value,
                    f"{vector_path}[{position}]",
                    maximum=option_counts[position] - 1,
                )
                for position, value in enumerate(values)
            )
            if checked in seen_included:
                raise ValidationError(f"{vector_path} duplicates another included vector")
            if any(_matches_ignored(checked, rule) for rule in ignored):
                raise ValidationError(f"{vector_path} also matches an ignored rule")
            seen_included.add(checked)
            included.append(checked)
        total_included += len(included)
        if total_included > 1 << 8:
            raise ValidationError("total included entries exceed the 8-bit start field")

        multiplier = 1
        for reverse_index, option_count in enumerate(reversed(option_counts)):
            _require_int(
                multiplier,
                f"{category_path}.place_multiplier[{reverse_index}]",
                maximum=_max_uint(16),
            )
            multiplier *= option_count
        space_size = _require_int(
            multiplier,
            f"{category_path}.space_size",
            minimum=1,
            maximum=_max_uint(32),
        )

        ignored_space_size = _count_ignored_space(option_counts, ignored)
        normal_size = size - len(included)
        _require_int(
            normal_size,
            f"{category_path}.normal_size",
            maximum=_max_uint(LAYOUT.category_range_bits),
        )
        _require_int(
            len(included),
            f"{category_path}.included_size",
            maximum=_max_uint(LAYOUT.category_range_bits),
        )
        legal_normal_space = space_size - ignored_space_size - len(included)
        if normal_size > legal_normal_space:
            raise ValidationError(
                f"{category_path}.size requires {normal_size} normal combinations, "
                f"but only {legal_normal_space} unique legal combinations exist"
            )

        specs.append(
            CategorySpec(
                name=name,
                size=size,
                attribute_names=tuple(attribute_names),
                option_counts=tuple(option_counts),
                ignored=tuple(ignored),
                included=tuple(included),
                space_size=space_size,
                ignored_space_size=ignored_space_size,
            )
        )

    total_size = sum(spec.size for spec in specs)
    _require_int(
        total_size,
        "settings.categories total size",
        minimum=1,
        maximum=_max_uint(LAYOUT.total_size_bits),
    )
    if len(specs) * 2 > _max_uint(8):
        raise ValidationError("random category count exceeds the legacy 8-bit loop bound")

    return tuple(specs), bytes(names)


def _name_register(specs: Sequence[CategorySpec]) -> tuple[str, dict[str, tuple[int, int]]]:
    names = bytearray()
    positions: dict[str, tuple[int, int]] = {}
    for spec in specs:
        for name in (spec.name, *spec.attribute_names):
            if name in positions:
                continue
            encoded = name.encode("utf-8")
            positions[name] = (len(names), len(encoded))
            names.extend(encoded)
    return names.decode("utf-8"), positions


def _words_from_bits(bit_string: str) -> tuple[int, ...]:
    words: list[int] = []
    for start in range(0, len(bit_string), 256):
        chunk = bit_string[start : start + 256].ljust(256, "0")
        words.append(int(chunk, 2))
    return tuple(words)


def _words_hash(words: Iterable[int]) -> str:
    raw = b"".join(word.to_bytes(32, "big") for word in words)
    return hashlib.sha256(raw).hexdigest()


def _register(
    *,
    category_count: int,
    total_size: int,
    random_shift: int,
    random_size: int,
    attribute_shift: int,
    ignored_shift: int,
    included_shift: int,
    bit_length: int,
    word_count: int,
) -> dict[str, int]:
    category_offsets = _field_offsets(LAYOUT.category_fields)
    attribute_offsets = _field_offsets(LAYOUT.attribute_fields)
    return {
        "SCHEMA_VERSION": SCHEMA_VERSION,
        "OPTION_BITSIZE": LAYOUT.option_bits,
        "MAX_ATTR_COUNT": LAYOUT.attribute_count,
        "CATEGORY_COUNT": category_count,
        "RCATEGORY_COUNT": category_count * 2,
        "TOTAL_SIZE": total_size,
        "CATEGORY_TABLE_SHIFT": 0,
        "CATEGORY_ENTRY_SIZE": LAYOUT.category_entry_bits,
        "CATEGORY_NAME_SHIFT_SHIFT": category_offsets["name_shift"],
        "CATEGORY_NAME_SHIFT_SIZE": 16,
        "CATEGORY_NAME_SIZE_SHIFT": category_offsets["name_size"],
        "CATEGORY_NAME_SIZE_SIZE": 4,
        "ATTR_START_SHIFT": category_offsets["attr_start"],
        "ATTR_START_SIZE": 8,
        "ATTR_COUNT_SHIFT": category_offsets["attr_count"],
        "ATTR_COUNT_SIZE": 3,
        "IGNORED_START_SHIFT": category_offsets["ignored_start"],
        "IGNORED_START_SIZE": 8,
        "IGNORED_SIZE_SHIFT": category_offsets["ignored_size"],
        "IGNORED_SIZE_SIZE": 4,
        "INCLUDED_START_SHIFT": category_offsets["included_start"],
        "INCLUDED_START_SIZE": 8,
        "INCLUDED_SIZE_SHIFT": category_offsets["included_size"],
        "INCLUDED_SIZE_SIZE": 4,
        "SPACE_SIZE_SHIFT": category_offsets["space_size"],
        "SPACE_SIZE_SIZE": 32,
        "RANDOM_CATEGORY_TABLE_SHIFT": random_shift,
        "RANDOM_CATEGORY_TABLE_SIZE": random_size,
        "RCATEGORY_ENTRY_SIZE": LAYOUT.category_range_bits,
        "RANGE_SIZE_SHIFT": 0,
        "RANGE_SIZE_SIZE": LAYOUT.category_range_bits,
        "ATTR_TABLE_SHIFT": attribute_shift,
        "ATTR_ENTRY_SIZE": LAYOUT.attribute_entry_bits,
        "ATTR_NAME_SHIFT_SHIFT": attribute_offsets["name_shift"],
        "ATTR_NAME_SHIFT_SIZE": 16,
        "ATTR_NAME_SIZE_SHIFT": attribute_offsets["name_size"],
        "ATTR_NAME_SIZE_SIZE": 4,
        "PLACE_MULTIPLIER_SHIFT": attribute_offsets["place_multiplier"],
        "PLACE_MULTIPLIER_SIZE": 16,
        "IGNORED_TABLE_SHIFT": ignored_shift,
        "IGNORE_ENTRY_SIZE": LAYOUT.ignore_entry_bits,
        "IGNORE_OPTIONS_LSB_SHIFT": LAYOUT.option_vector_bits,
        "IGNORE_OPTIONS_SIZE": LAYOUT.option_vector_bits,
        "IGNORE_POSITION_MASK_LSB_SHIFT": 0,
        "IGNORE_POSITION_MASK_SIZE": LAYOUT.option_vector_bits,
        "INCLUDED_TABLE_SHIFT": included_shift,
        "INCLUDE_ENTRY_SIZE": LAYOUT.include_entry_bits,
        "OPTIONS_ARRAY_SHIFT": 0,
        "OPTIONS_ARRAY_SIZE": LAYOUT.option_vector_bits,
        "BIT_LENGTH": bit_length,
        "WORD_COUNT": word_count,
    }


def compile_settings(settings: Any) -> CompiledMemory:
    specs, _ = _validate_settings(settings)
    maximum_rejection_run = max((_maximum_rejection_run(spec) for spec in specs), default=0)
    if maximum_rejection_run >= MAX_TRAIT_SEARCH_ATTEMPTS:
        raise ValidationError(
            "fixed consumer traversal can encounter "
            f"{maximum_rejection_run} consecutive rejected combinations"
        )
    names, name_positions = _name_register(specs)

    attribute_parts: list[str] = []
    attribute_meta: list[tuple[int, int, int]] = []
    attribute_start = 0
    for category_index, spec in enumerate(specs):
        attribute_meta.append((attribute_start, len(spec.attribute_names), spec.space_size))
        multiplier = 1
        for reverse_index in range(LAYOUT.attribute_count - 1, -1, -1):
            name = spec.attribute_names[reverse_index]
            name_shift, name_size = name_positions[name]
            attribute_parts.append(
                _pack_named_fields(
                    {
                        "name_shift": name_shift,
                        "name_size": name_size,
                        "place_multiplier": multiplier,
                    },
                    LAYOUT.attribute_fields,
                    f"attribute_table[{category_index}][{reverse_index}]",
                )
            )
            multiplier *= spec.option_counts[reverse_index]
            attribute_start += 1

    ignored_parts: list[str] = []
    ignored_meta: list[tuple[int, int]] = []
    ignored_start = 0
    for category_index, spec in enumerate(specs):
        ignored_meta.append((ignored_start, len(spec.ignored)))
        for rule_index, (pos0, option0, pos1, option1) in enumerate(spec.ignored):
            ignored_options = [0] * LAYOUT.attribute_count
            position_mask = [0] * LAYOUT.attribute_count
            ignored_options[pos0] = option0
            ignored_options[pos1] = option1
            position_mask[pos0] = _max_uint(LAYOUT.option_bits)
            position_mask[pos1] = _max_uint(LAYOUT.option_bits)
            record = _pack_option_vector(
                ignored_options, f"ignored_table[{category_index}][{rule_index}].options"
            ) + _pack_option_vector(
                position_mask, f"ignored_table[{category_index}][{rule_index}].mask"
            )
            if len(record) != LAYOUT.ignore_entry_bits:
                raise AssertionError("ignore entry size drifted from the declared layout")
            ignored_parts.append(record)
            ignored_start += 1

    included_parts: list[str] = []
    included_meta: list[tuple[int, int]] = []
    included_start = 0
    for category_index, spec in enumerate(specs):
        included_meta.append((included_start, len(spec.included)))
        for vector_index, vector in enumerate(spec.included):
            included_parts.append(
                _pack_option_vector(vector, f"included_table[{category_index}][{vector_index}]")
            )
            included_start += 1

    category_parts: list[str] = []
    for category_index, spec in enumerate(specs):
        name_shift, name_size = name_positions[spec.name]
        attr_start, attr_count, space_size = attribute_meta[category_index]
        ignored_start_value, ignored_size = ignored_meta[category_index]
        included_start_value, included_size = included_meta[category_index]
        category_parts.append(
            _pack_named_fields(
                {
                    "name_shift": name_shift,
                    "name_size": name_size,
                    "attr_start": attr_start,
                    "attr_count": attr_count,
                    "ignored_start": ignored_start_value,
                    "ignored_size": ignored_size,
                    "included_start": included_start_value,
                    "included_size": included_size,
                    "space_size": space_size,
                },
                LAYOUT.category_fields,
                f"category_table[{category_index}]",
            )
        )

    random_entries_lsb_first: list[int] = []
    for spec in specs:
        random_entries_lsb_first.extend((spec.normal_size, len(spec.included)))
    random_parts = [
        _encode_uint(value, LAYOUT.category_range_bits, f"random_category[{index}]")
        for index, value in reversed(list(enumerate(random_entries_lsb_first)))
    ]

    category_table = "".join(category_parts)
    random_table = "".join(random_parts)
    attribute_table = "".join(attribute_parts)
    ignored_table = "".join(ignored_parts)
    included_table = "".join(included_parts)

    random_shift = len(category_table)
    attribute_shift = random_shift + len(random_table)
    ignored_shift = attribute_shift + len(attribute_table)
    included_shift = ignored_shift + len(ignored_table)
    bit_string = category_table + random_table + attribute_table + ignored_table + included_table
    if len(bit_string) > _max_uint(LAYOUT.max_stream_bits):
        raise ValidationError("encoded bit stream exceeds the legacy 16-bit shift range")

    words = _words_from_bits(bit_string)
    total_size = sum(spec.size for spec in specs)
    register = _register(
        category_count=len(specs),
        total_size=total_size,
        random_shift=random_shift,
        random_size=len(random_table),
        attribute_shift=attribute_shift,
        ignored_shift=ignored_shift,
        included_shift=included_shift,
        bit_length=len(bit_string),
        word_count=len(words),
    )

    categories = _require_mapping(settings, "settings")["categories"]
    canonical_categories = json.dumps(
        categories,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return CompiledMemory(
        names=names,
        bit_string=bit_string,
        words=words,
        register=register,
        categories_sha256=hashlib.sha256(canonical_categories).hexdigest(),
        words_sha256=_words_hash(words),
        total_size=total_size,
        category_count=len(specs),
        max_rejection_run=maximum_rejection_run,
    )


def load_settings(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as source:
            return _require_mapping(json.load(source), "settings")
    except json.JSONDecodeError as error:
        raise ValidationError(f"{path}: invalid JSON: {error.msg}") from error


def render_memory_json(compiled: CompiledMemory) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "categories_sha256": compiled.categories_sha256,
        "words_sha256": compiled.words_sha256,
        "bit_length": compiled.bit_length,
        "max_rejection_run": compiled.max_rejection_run,
        "names": compiled.names,
        "words": list(compiled.words),
        # Retain the legacy keys for consumers while making their representation explicit.
        "hex": list(compiled.words),
        "register": dict(compiled.register),
        "bin": compiled.bit_string,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_solidity(compiled: CompiledMemory) -> str:
    register = compiled.register
    lines = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by alvara-memgenerator. Do not edit by hand.",
        "pragma solidity 0.8.38;",
        "",
        "library AlvaraTraitData {",
        "    error WordIndexOutOfBounds(uint256 index);",
        "",
        f"    uint256 internal constant SCHEMA_VERSION = {SCHEMA_VERSION};",
        f"    uint256 internal constant OPTION_BITS = {LAYOUT.option_bits};",
        f"    uint256 internal constant ATTRIBUTE_COUNT = {LAYOUT.attribute_count};",
        f"    uint256 internal constant CATEGORY_COUNT = {compiled.category_count};",
        f"    uint256 internal constant RANDOM_CATEGORY_COUNT = {compiled.category_count * 2};",
        f"    uint256 internal constant TOTAL_SIZE = {compiled.total_size};",
        f"    uint256 internal constant BIT_LENGTH = {compiled.bit_length};",
        f"    uint256 internal constant WORD_COUNT = {len(compiled.words)};",
        f"    uint256 internal constant COMBINATION_CURSOR_DELTA = {COMBINATION_CURSOR_DELTA};",
        f"    uint256 internal constant MAX_REJECTION_RUN = {compiled.max_rejection_run};",
        "",
        f"    uint256 internal constant CATEGORY_ENTRY_BITS = {LAYOUT.category_entry_bits};",
        f"    uint256 internal constant RANDOM_CATEGORY_ENTRY_BITS = {LAYOUT.category_range_bits};",
        f"    uint256 internal constant ATTRIBUTE_ENTRY_BITS = {LAYOUT.attribute_entry_bits};",
        f"    uint256 internal constant IGNORE_ENTRY_BITS = {LAYOUT.ignore_entry_bits};",
        f"    uint256 internal constant INCLUDE_ENTRY_BITS = {LAYOUT.include_entry_bits};",
        f"    uint256 internal constant OPTION_VECTOR_BITS = {LAYOUT.option_vector_bits};",
        "",
        f"    uint256 internal constant CATEGORY_TABLE_OFFSET = {register['CATEGORY_TABLE_SHIFT']};",
        f"    uint256 internal constant RANDOM_CATEGORY_TABLE_OFFSET = {register['RANDOM_CATEGORY_TABLE_SHIFT']};",
        f"    uint256 internal constant ATTRIBUTE_TABLE_OFFSET = {register['ATTR_TABLE_SHIFT']};",
        f"    uint256 internal constant IGNORED_TABLE_OFFSET = {register['IGNORED_TABLE_SHIFT']};",
        f"    uint256 internal constant INCLUDED_TABLE_OFFSET = {register['INCLUDED_TABLE_SHIFT']};",
        f"    uint256 internal constant IGNORE_OPTIONS_LSB_SHIFT = {register['IGNORE_OPTIONS_LSB_SHIFT']};",
        f"    uint256 internal constant IGNORE_POSITION_MASK_LSB_SHIFT = {register['IGNORE_POSITION_MASK_LSB_SHIFT']};",
        "",
        f"    bytes32 internal constant CATEGORIES_SHA256 = 0x{compiled.categories_sha256};",
        f"    bytes32 internal constant WORDS_SHA256 = 0x{compiled.words_sha256};",
        "",
        "    function word(uint256 index) internal pure returns (uint256) {",
    ]
    lines.extend(
        f"        if (index == {index}) return {word};"
        for index, word in enumerate(compiled.words)
    )
    lines.extend(
        (
            "        revert WordIndexOutOfBounds(index);",
            "    }",
            "",
            "    function words() internal pure returns (uint256[] memory result) {",
            "        result = new uint256[](WORD_COUNT);",
            "        for (uint256 index; index < WORD_COUNT; ++index) {",
            "            result[index] = word(index);",
            "        }",
            "    }",
            "}",
            "",
        )
    )
    return "\n".join(lines)


def _stage_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, 0o644)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return temporary_path


def _fsync_directory(path: Path) -> None:
    """Persist rename operations when the platform supports directory fsync."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            return
    finally:
        os.close(descriptor)


def write_outputs(
    memory_path: Path,
    memory_content: str,
    solidity_path: Path,
    solidity_content: str,
) -> None:
    if memory_path.resolve() == solidity_path.resolve():
        raise ValidationError("memory and Solidity outputs must use different paths")

    staged: list[tuple[Path, Path]] = []
    backups: list[tuple[Path, Path]] = []
    installed: list[Path] = []
    try:
        staged.append((_stage_text(memory_path, memory_content), memory_path))
        staged.append((_stage_text(solidity_path, solidity_content), solidity_path))
        for _temporary_path, destination in staged:
            if destination.exists() or destination.is_symlink():
                descriptor, backup_name = tempfile.mkstemp(
                    prefix=f".{destination.name}.", suffix=".backup", dir=destination.parent
                )
                os.close(descriptor)
                backup_path = Path(backup_name)
                backup_path.unlink()
                os.replace(destination, backup_path)
                backups.append((backup_path, destination))
        for temporary_path, destination in staged:
            os.replace(temporary_path, destination)
            installed.append(destination)
        for parent in {destination.parent for _, destination in staged}:
            _fsync_directory(parent)
    except Exception:
        for destination in installed:
            destination.unlink(missing_ok=True)
        for backup_path, destination in reversed(backups):
            if backup_path.exists() or backup_path.is_symlink():
                os.replace(backup_path, destination)
        for parent in {destination.parent for _, destination in staged}:
            _fsync_directory(parent)
        raise
    finally:
        for temporary_path, _ in staged:
            temporary_path.unlink(missing_ok=True)
        for backup_path, _ in backups:
            backup_path.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile validated Alvara settings into deterministic memory artifacts."
    )
    parser.add_argument("--settings", required=True, type=Path, help="input settings JSON")
    parser.add_argument("--memory-out", required=True, type=Path, help="output memory JSON")
    parser.add_argument(
        "--solidity-out", required=True, type=Path, help="output AlvaraTraitData library"
    )
    return parser


def cli(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        compiled = compile_settings(load_settings(arguments.settings))
        write_outputs(
            arguments.memory_out,
            render_memory_json(compiled),
            arguments.solidity_out,
            render_solidity(compiled),
        )
    except (OSError, ValidationError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
