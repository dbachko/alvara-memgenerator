from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import main


REPOSITORY = Path(__file__).resolve().parents[1]
BACKEND_SETTINGS = REPOSITORY.parent / "alvara-backend" / "settings.json"
GOLDEN_MEMORY = REPOSITORY / "generated" / "memory.json"
GOLDEN_SOLIDITY = REPOSITORY / "generated" / "AlvaraTraitData.sol"
CONTRACT_SOLIDITY = (
    REPOSITORY.parent / "alvara-smart-contract" / "contracts" / "generated" / "AlvaraTraitData.sol"
)


def option(attribute: int, index: int) -> dict[str, object]:
    return {
        "name": f"option-{attribute}-{index}",
        "pics": [{"path": f"layer-{attribute}-{index}.png", "z": attribute * 10}],
    }


def settings_fixture() -> dict[str, object]:
    counts = (2, 1, 2, 1, 1, 1, 1)
    attributes = [
        {
            "name": f"attr-{attribute_index}",
            "options": [
                option(attribute_index, option_index)
                for option_index in range(option_count)
            ],
        }
        for attribute_index, option_count in enumerate(counts)
    ]
    return {
        "assets_path": "assets",
        "image": 350,
        "external": 3000,
        "categories": [
            {
                "name": "sample",
                "size": 3,
                "attributes": attributes,
                "ignored": [[0, 1, 2, 1]],
                "included": [[0, 0, 0, 0, 0, 0, 0]],
            }
        ],
    }


def packed_options(values: list[int]) -> int:
    packed = 0
    for value in values:
        packed = (packed << 5) | value
    return packed


class PackingTests(unittest.TestCase):
    def test_ignore_records_use_two_five_bit_vectors(self) -> None:
        compiled = main.compile_settings(settings_fixture())
        register = compiled.register
        self.assertEqual(register["IGNORE_ENTRY_SIZE"], 70)

        start = register["IGNORED_TABLE_SHIFT"]
        record = int(compiled.bit_string[start : start + 70], 2)
        low_mask = (1 << 35) - 1
        ignored_options = record >> 35
        position_mask = record & low_mask
        expected_options = (1 << 30) | (1 << 20)
        expected_mask = (31 << 30) | (31 << 20)
        self.assertEqual(ignored_options, expected_options)
        self.assertEqual(position_mask, expected_mask)

    def test_all_offsets_are_derived_from_table_lengths(self) -> None:
        compiled = main.compile_settings(settings_fixture())
        register = compiled.register
        self.assertEqual(register["CATEGORY_ENTRY_SIZE"], 87)
        self.assertEqual(register["RANDOM_CATEGORY_TABLE_SHIFT"], 87)
        self.assertEqual(register["ATTR_TABLE_SHIFT"], 87 + 26)
        self.assertEqual(register["IGNORED_TABLE_SHIFT"], 87 + 26 + 7 * 36)
        self.assertEqual(register["INCLUDED_TABLE_SHIFT"], register["IGNORED_TABLE_SHIFT"] + 70)
        self.assertEqual(register["BIT_LENGTH"], len(compiled.bit_string))
        self.assertEqual(register["WORD_COUNT"], len(compiled.words))

    def test_output_is_deterministic_and_hashes_padded_words(self) -> None:
        first = main.compile_settings(settings_fixture())
        second = main.compile_settings(copy.deepcopy(settings_fixture()))
        self.assertEqual(main.render_memory_json(first), main.render_memory_json(second))
        self.assertEqual(main.render_solidity(first), main.render_solidity(second))
        raw_words = b"".join(word.to_bytes(32, "big") for word in first.words)
        self.assertEqual(first.words_sha256, hashlib.sha256(raw_words).hexdigest())
        self.assertLess(first.max_rejection_run, main.MAX_TRAIT_SEARCH_ATTEMPTS)

    def test_solidity_contains_the_compiled_words(self) -> None:
        compiled = main.compile_settings(settings_fixture())
        source = main.render_solidity(compiled)
        self.assertIn("library AlvaraTraitData", source)
        self.assertIn("pragma solidity 0.8.38;", source)
        self.assertIn(
            "function word(uint256 index) internal pure returns (uint256)", source
        )
        self.assertIn(
            "result = new uint256[](WORD_COUNT);",
            source,
        )
        for index, word in enumerate(compiled.words):
            self.assertIn(f"if (index == {index}) return {word};", source)
        self.assertIn("revert WordIndexOutOfBounds(index);", source)


class ValidationTests(unittest.TestCase):
    def assert_invalid(self, settings: dict[str, object]) -> None:
        with self.assertRaises(main.ValidationError):
            main.compile_settings(settings)

    def test_rejects_wrong_attribute_count(self) -> None:
        value = settings_fixture()
        value["categories"][0]["attributes"].pop()
        self.assert_invalid(value)

    def test_rejects_duplicate_category_names(self) -> None:
        value = settings_fixture()
        value["categories"].append(copy.deepcopy(value["categories"][0]))
        self.assert_invalid(value)

    def test_rejects_empty_options(self) -> None:
        value = settings_fixture()
        value["categories"][0]["attributes"][0]["options"] = []
        self.assert_invalid(value)

    def test_rejects_duplicate_option_names(self) -> None:
        value = settings_fixture()
        options = value["categories"][0]["attributes"][0]["options"]
        options[1]["name"] = options[0]["name"]
        self.assert_invalid(value)

    def test_rejects_duplicate_picture_records(self) -> None:
        value = settings_fixture()
        pictures = value["categories"][0]["attributes"][0]["options"][0]["pics"]
        pictures.append(dict(pictures[0]))
        self.assert_invalid(value)

    def test_rejects_option_count_overflow(self) -> None:
        value = settings_fixture()
        value["categories"][0]["attributes"][0]["options"] = [
            option(0, index) for index in range(33)
        ]
        self.assert_invalid(value)

    def test_rejects_duplicate_included_vectors(self) -> None:
        value = settings_fixture()
        included = value["categories"][0]["included"]
        included.append(list(included[0]))
        self.assert_invalid(value)

    def test_rejects_wrong_included_vector_length(self) -> None:
        value = settings_fixture()
        value["categories"][0]["included"][0].pop()
        self.assert_invalid(value)

    def test_rejects_reversed_duplicate_ignored_rules(self) -> None:
        value = settings_fixture()
        value["categories"][0]["ignored"].append([2, 1, 0, 1])
        self.assert_invalid(value)

    def test_rejects_wrong_ignored_rule_length(self) -> None:
        value = settings_fixture()
        value["categories"][0]["ignored"][0].pop()
        self.assert_invalid(value)

    def test_rejects_out_of_range_included_option(self) -> None:
        value = settings_fixture()
        value["categories"][0]["included"][0][1] = 1
        self.assert_invalid(value)

    def test_rejects_out_of_range_ignored_option(self) -> None:
        value = settings_fixture()
        value["categories"][0]["ignored"][0][1] = 2
        self.assert_invalid(value)

    def test_rejects_included_vector_matching_ignored_rule(self) -> None:
        value = settings_fixture()
        value["categories"][0]["included"][0] = [1, 0, 1, 0, 0, 0, 0]
        self.assert_invalid(value)

    def test_rejects_impossible_unique_size(self) -> None:
        value = settings_fixture()
        value["categories"][0]["size"] = 4
        self.assert_invalid(value)

    def test_rejects_same_attribute_twice_in_ignore(self) -> None:
        value = settings_fixture()
        value["categories"][0]["ignored"][0] = [0, 0, 0, 1]
        self.assert_invalid(value)

    def test_rejects_name_width_overflow(self) -> None:
        value = settings_fixture()
        value["categories"][0]["name"] = "category-name-is-too-long"
        self.assert_invalid(value)

    def test_rejects_bit_width_overflow(self) -> None:
        with self.assertRaises(main.ValidationError):
            main._encode_uint(32, 5, "option")

    def test_rejects_same_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "same"
            with self.assertRaises(main.ValidationError):
                main.write_outputs(path, "one", path, "two")

    def test_failed_second_publish_restores_both_previous_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            memory_path = root / "memory.json"
            solidity_path = root / "AlvaraTraitData.sol"
            memory_path.write_text("old-memory", encoding="utf-8")
            solidity_path.write_text("old-solidity", encoding="utf-8")
            real_replace = main.os.replace

            def fail_second_install(source: str | Path, destination: str | Path) -> None:
                source_path = Path(source)
                destination_path = Path(destination)
                if destination_path == solidity_path and source_path.suffix == ".tmp":
                    raise OSError("simulated second publish failure")
                real_replace(source_path, destination_path)

            with mock.patch.object(main.os, "replace", side_effect=fail_second_install):
                with self.assertRaisesRegex(OSError, "simulated second publish failure"):
                    main.write_outputs(memory_path, "new-memory", solidity_path, "new-solidity")

            self.assertEqual(memory_path.read_text(encoding="utf-8"), "old-memory")
            self.assertEqual(solidity_path.read_text(encoding="utf-8"), "old-solidity")
            self.assertEqual(list(root.glob(".*.tmp")), [])
            self.assertEqual(list(root.glob(".*.backup")), [])


class CliTests(unittest.TestCase):
    def test_cli_requires_explicit_paths_and_writes_complete_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings_path = root / "settings.json"
            memory_path = root / "nested" / "memory.json"
            solidity_path = root / "nested" / "AlvaraTraitData.sol"
            settings_path.write_text(json.dumps(settings_fixture()), encoding="utf-8")
            result = main.cli(
                [
                    "--settings",
                    str(settings_path),
                    "--memory-out",
                    str(memory_path),
                    "--solidity-out",
                    str(solidity_path),
                ]
            )
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(memory_path.read_text())["schema_version"], 1)
            self.assertIn("library AlvaraTraitData", solidity_path.read_text())
            self.assertEqual(list(memory_path.parent.glob(".*.tmp")), [])


@unittest.skipUnless(BACKEND_SETTINGS.exists(), "sibling backend settings are not available")
class RealSettingsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = main.load_settings(BACKEND_SETTINGS)
        cls.compiled = main.compile_settings(cls.settings)

    def test_real_collection_layout(self) -> None:
        self.assertEqual(self.compiled.category_count, 5)
        self.assertEqual(self.compiled.total_size, 10_000)
        self.assertEqual(self.compiled.register["RANDOM_CATEGORY_TABLE_SHIFT"], 435)
        self.assertEqual(self.compiled.register["ATTR_TABLE_SHIFT"], 565)
        self.assertEqual(self.compiled.register["IGNORED_TABLE_SHIFT"], 1825)
        self.assertEqual(self.compiled.register["INCLUDED_TABLE_SHIFT"], 2525)
        self.assertEqual(self.compiled.bit_length, 3575)
        self.assertEqual(len(self.compiled.words), 14)
        self.assertEqual(self.compiled.max_rejection_run, 1)

    def test_real_categories_hash_is_pinned(self) -> None:
        self.assertEqual(
            self.compiled.categories_sha256,
            "111233cde9dd315253ab7db062f1ae406d9acf2d29262b4bdc05bd8697d7c4bc",
        )

    def test_real_ignored_rules_round_trip(self) -> None:
        entry_index = 0
        table_start = self.compiled.register["IGNORED_TABLE_SHIFT"]
        low_mask = (1 << 35) - 1
        for category in self.settings["categories"]:
            for pos0, option0, pos1, option1 in category["ignored"]:
                start = table_start + entry_index * 70
                record = int(self.compiled.bit_string[start : start + 70], 2)
                expected_options = [0] * 7
                expected_options[pos0] = option0
                expected_options[pos1] = option1
                expected_mask = [0] * 7
                expected_mask[pos0] = 31
                expected_mask[pos1] = 31
                self.assertEqual(record >> 35, packed_options(expected_options))
                self.assertEqual(record & low_mask, packed_options(expected_mask))
                entry_index += 1
        self.assertEqual(entry_index, 10)

    def test_real_included_vectors_round_trip(self) -> None:
        entry_index = 0
        table_start = self.compiled.register["INCLUDED_TABLE_SHIFT"]
        for category in self.settings["categories"]:
            for vector in category["included"]:
                start = table_start + entry_index * 35
                record = int(self.compiled.bit_string[start : start + 35], 2)
                self.assertEqual(record, packed_options(vector))
                entry_index += 1
        self.assertEqual(entry_index, 30)

    def test_checked_in_memory_is_exact_golden_output(self) -> None:
        self.assertEqual(
            GOLDEN_MEMORY.read_text(encoding="utf-8"),
            main.render_memory_json(self.compiled),
        )

    def test_checked_in_solidity_is_exact_golden_output(self) -> None:
        self.assertEqual(
            GOLDEN_SOLIDITY.read_text(encoding="utf-8"),
            main.render_solidity(self.compiled),
        )

    @unittest.skipUnless(CONTRACT_SOLIDITY.exists(), "sibling contract checkout is not available")
    def test_contract_copy_is_exact_generated_output(self) -> None:
        self.assertEqual(
            CONTRACT_SOLIDITY.read_text(encoding="utf-8"),
            main.render_solidity(self.compiled),
        )


if __name__ == "__main__":
    unittest.main()
