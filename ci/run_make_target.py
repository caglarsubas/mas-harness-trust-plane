#!/usr/bin/env python3
"""Closed cumulative packet descriptor dispatcher using direct argv only."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


SCHEMA_VERSION = "harness.planeon.ai/make-target-descriptor/v1alpha1"
PACKET_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
TARGET_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
ALLOWED_VARIABLES = {"BACKEND", "CAMPAIGN", "MODULE", "PACK", "PROVIDERS"}
FORBIDDEN_EXECUTABLES = {"bash", "dash", "env", "sh", "zsh"}


class TargetDescriptorError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TargetDescriptorError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class Rule:
    packet_id: str
    name: str
    variables: Mapping[str, frozenset[str]]
    commands: tuple[tuple[str | tuple[str, str], ...], ...]

    def matches(self, supplied: Mapping[str, str]) -> bool:
        return set(supplied) == set(self.variables) and all(supplied[name] in values for name, values in self.variables.items())

    def render(self, supplied: Mapping[str, str]) -> tuple[tuple[str, ...], ...]:
        return tuple(tuple(supplied[item[1]] if isinstance(item, tuple) else item for item in command) for command in self.commands)


def _object(value: object, message: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TargetDescriptorError(message)
    return value


def _variables(value: object, context: str) -> Mapping[str, frozenset[str]]:
    raw = _object(value, f"acceptedVariables must be an object: {context}")
    result: dict[str, frozenset[str]] = {}
    for name, specification in raw.items():
        if name not in ALLOWED_VARIABLES:
            raise TargetDescriptorError(f"undeclared Make variable: {name}")
        rule = _object(specification, f"variable rule must be an object: {context}/{name}")
        values = [rule["const"]] if set(rule) == {"const"} else rule.get("enum") if set(rule) == {"enum"} else None
        if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values) or len(values) != len(set(values)):
            raise TargetDescriptorError(f"variable rule is not closed: {context}/{name}")
        result[name] = frozenset(values)
    return result


def _commands(value: object, accepted: Mapping[str, frozenset[str]], context: str) -> tuple[tuple[str | tuple[str, str], ...], ...]:
    if not isinstance(value, list) or not value:
        raise TargetDescriptorError(f"argvTemplate is empty: {context}")
    result: list[tuple[str | tuple[str, str], ...]] = []
    for raw in value:
        if not isinstance(raw, list) or not raw:
            raise TargetDescriptorError(f"argv command is empty: {context}")
        command: list[str | tuple[str, str]] = []
        for item in raw:
            if isinstance(item, str) and item and "\x00" not in item and "\n" not in item:
                command.append(item)
            elif isinstance(item, dict) and set(item) == {"variable"} and item["variable"] in accepted:
                command.append(("variable", str(item["variable"])))
            else:
                raise TargetDescriptorError(f"argv argument is not closed: {context}")
        if not isinstance(command[0], str) or Path(command[0]).name in FORBIDDEN_EXECUTABLES:
            raise TargetDescriptorError(f"shell transport is forbidden: {context}")
        result.append(tuple(command))
    return tuple(result)


def load_rules(directory: Path) -> tuple[Rule, ...]:
    if not directory.is_dir() or directory.is_symlink():
        raise TargetDescriptorError("descriptor directory is absent or linked")
    rules: list[Rule] = []
    packet_ids: set[str] = set()
    signatures: set[tuple[str, str, tuple[tuple[str, tuple[str, ...]], ...]]] = set()
    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise TargetDescriptorError("descriptor must be a regular file")
        try:
            descriptor = _object(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object), "descriptor must be an object")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise TargetDescriptorError(f"invalid target descriptor: {path.name}") from exc
        if set(descriptor) != {"schemaVersion", "packetId", "targets"} or descriptor["schemaVersion"] != SCHEMA_VERSION:
            raise TargetDescriptorError(f"descriptor fields or schema are invalid: {path.name}")
        packet_id = descriptor["packetId"]
        if not isinstance(packet_id, str) or PACKET_PATTERN.fullmatch(packet_id) is None or path.name != f"{packet_id.lower()}.json":
            raise TargetDescriptorError(f"owner or filename mismatch: {path.name}")
        if packet_id in packet_ids:
            raise TargetDescriptorError(f"duplicate packet descriptor: {packet_id}")
        packet_ids.add(packet_id)
        if not isinstance(descriptor["targets"], list) or not descriptor["targets"]:
            raise TargetDescriptorError(f"descriptor has no targets: {path.name}")
        for index, raw_target in enumerate(descriptor["targets"]):
            target = _object(raw_target, f"target must be an object: {path.name}/{index}")
            if set(target) != {"name", "acceptedVariables", "argvTemplate"}:
                raise TargetDescriptorError(f"target fields are closed: {path.name}/{index}")
            name = target["name"]
            if not isinstance(name, str) or TARGET_PATTERN.fullmatch(name) is None:
                raise TargetDescriptorError(f"invalid target name: {path.name}/{index}")
            variables = _variables(target["acceptedVariables"], f"{path.name}/{name}")
            signature = (packet_id, name, tuple(sorted((key, tuple(sorted(values))) for key, values in variables.items())))
            if signature in signatures:
                raise TargetDescriptorError(f"duplicate or overlapping target rule: {packet_id}/{name}")
            signatures.add(signature)
            rules.append(Rule(packet_id, name, variables, _commands(target["argvTemplate"], variables, f"{path.name}/{name}")))
    if not rules:
        raise TargetDescriptorError("no target descriptors were found")
    return tuple(sorted(rules, key=lambda rule: (rule.packet_id, rule.name)))


def dispatch(target: str, supplied: Mapping[str, str], directory: Path) -> int:
    if TARGET_PATTERN.fullmatch(target) is None:
        raise TargetDescriptorError("target name is invalid")
    matches = [rule for rule in load_rules(directory) if rule.name == target and rule.matches(supplied)]
    if not matches:
        raise TargetDescriptorError(f"zero applicable handlers: {target}")
    owners = [rule.packet_id for rule in matches]
    if len(owners) != len(set(owners)):
        raise TargetDescriptorError(f"multiple applicable handlers from one packet: {target}")
    for rule in matches:
        for command in rule.render(supplied):
            print(f"make-handler packet={rule.packet_id} argv={json.dumps(command, separators=(',', ':'))}", flush=True)
            completed = subprocess.run(command, shell=False, check=False)
            if completed.returncode:
                return completed.returncode
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print("one Make target is required", file=sys.stderr)
        return 2
    try:
        inherited = {name: os.environ[name] for name in ALLOWED_VARIABLES if os.environ.get(name)}
        return dispatch(arguments[0], inherited, Path(__file__).with_name("targets"))
    except TargetDescriptorError as exc:
        print(f"Make dispatch refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
