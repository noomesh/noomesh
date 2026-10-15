# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change: every old `video_memory` spelling keeps working for one
release after 0.6.0, warns once, and loses to the new spelling.

Planted: drop the `mode="before"` validator on AppConfig and the first test
fails (the old section is ignored); flip the precedence in
`migrate_recall_memory_section` and the both-present test fails.
"""
from __future__ import annotations

import pytest

import noomesh.config as cfg


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch):
    seen: list[tuple[str, str, bool]] = []
    monkeypatch.setattr(cfg, "_deprecations_warned", set())
    real = cfg._warn_deprecated

    def spy(old, new, *, both=False):
        seen.append((old, new, both))
        real(old, new, both=both)

    monkeypatch.setattr(cfg, "_warn_deprecated", spy)
    monkeypatch.delenv("NOO_RECALL_MEMORY_PATH", raising=False)
    monkeypatch.delenv("NOO_VIDEO_MEMORY_PATH", raising=False)
    return seen


def test_old_section_is_read_as_the_new_one_and_warns(_fresh_warnings):
    c = cfg.AppConfig.model_validate({"video_memory": {"prune_after_days": 42}})
    assert c.recall_memory.prune_after_days == 42
    assert c.video_memory is c.recall_memory, "deprecated attribute reads the same section"
    assert ("video_memory", "recall_memory", False) in _fresh_warnings


def test_new_section_needs_no_warning(_fresh_warnings):
    c = cfg.AppConfig.model_validate({"recall_memory": {"prune_after_days": 7}})
    assert c.recall_memory.prune_after_days == 7
    assert _fresh_warnings == []


def test_both_present_new_wins_with_a_warning_naming_the_duplicate(_fresh_warnings):
    c = cfg.AppConfig.model_validate({"video_memory": {"prune_after_days": 42},
                                      "recall_memory": {"prune_after_days": 7}})
    assert c.recall_memory.prune_after_days == 7
    assert ("video_memory", "recall_memory", True) in _fresh_warnings


def test_the_deprecation_warns_once_per_process(monkeypatch):
    monkeypatch.setattr(cfg, "_deprecations_warned", set())
    calls = []
    monkeypatch.setattr("noomesh._logging.get_logger",
                        lambda name: type("L", (), {"warning": lambda self, ev, **kw: calls.append((ev, kw))})())
    for _ in range(3):
        cfg.AppConfig.model_validate({"video_memory": {}})
    assert len(calls) == 1, calls
    ev, kw = calls[0]
    assert ev == "deprecated_config" and kw["old"] == "video_memory" and kw["new"] == "recall_memory"


def test_old_env_is_honoured_with_a_warning(monkeypatch, _fresh_warnings):
    monkeypatch.setenv("NOO_VIDEO_MEMORY_PATH", "/old")
    assert cfg.RecallMemoryConfig().storage_dir == "/old"
    assert ("NOO_VIDEO_MEMORY_PATH", "NOO_RECALL_MEMORY_PATH", False) in _fresh_warnings


def test_both_env_present_new_wins_and_differing_values_warn(monkeypatch, _fresh_warnings):
    monkeypatch.setenv("NOO_VIDEO_MEMORY_PATH", "/old")
    monkeypatch.setenv("NOO_RECALL_MEMORY_PATH", "/new")
    assert cfg.RecallMemoryConfig().storage_dir == "/new"
    assert ("NOO_VIDEO_MEMORY_PATH", "NOO_RECALL_MEMORY_PATH", True) in _fresh_warnings


def test_both_env_equal_is_the_compose_transition_state_and_is_quiet(monkeypatch, _fresh_warnings):
    monkeypatch.setenv("NOO_VIDEO_MEMORY_PATH", "/data/video_memory")
    monkeypatch.setenv("NOO_RECALL_MEMORY_PATH", "/data/video_memory")
    assert cfg.recall_memory_path_env() == "/data/video_memory"
    assert _fresh_warnings == []


def test_deprecated_class_name_is_the_same_class():
    assert cfg.VideoMemoryConfig is cfg.RecallMemoryConfig


def _save(tmp_path, monkeypatch, original: dict, data: dict) -> dict:
    import yaml

    path = tmp_path / "noomesh.yaml"
    monkeypatch.setattr(cfg, "_original_yaml_data", original)
    cfg.save_config(cfg.AppConfig.model_validate(data), path)
    return yaml.safe_load(path.read_text())


def test_save_never_renames_the_operators_key(tmp_path, monkeypatch):
    written = _save(tmp_path, monkeypatch, {"video_memory": {"prune_after_days": 42}},
                    {"video_memory": {"prune_after_days": 42}})
    assert "recall_memory" not in written, written
    assert written["video_memory"]["prune_after_days"] == 42


def test_save_keeps_a_new_key_as_the_new_key(tmp_path, monkeypatch):
    written = _save(tmp_path, monkeypatch, {"recall_memory": {"prune_after_days": 7}},
                    {"recall_memory": {"prune_after_days": 7}})
    assert "video_memory" not in written, written
    assert written["recall_memory"]["prune_after_days"] == 7


def test_save_creates_the_old_key_while_evolve_reads_it(tmp_path, monkeypatch):
    written = _save(tmp_path, monkeypatch, {}, {"recall_memory": {"prune_after_days": 9}})
    assert written.get("video_memory", {}).get("prune_after_days") == 9, written
    assert "recall_memory" not in written


def test_a_runtime_update_to_the_old_name_is_not_lost(tmp_path, monkeypatch):
    import yaml

    path = tmp_path / "noomesh.yaml"
    path.write_text("video_memory:\n  prune_after_days: 42\n")
    monkeypatch.setattr(cfg, "_runtime_config", cfg.AppConfig.model_validate({"video_memory": {"prune_after_days": 42}}))
    monkeypatch.setattr(cfg, "_runtime_config_path", path)
    monkeypatch.setattr(cfg, "_original_yaml_data", {"video_memory": {"prune_after_days": 42}})
    out = cfg.update_runtime_config("video_memory", {"prune_after_days": 30})
    assert out.recall_memory.prune_after_days == 30
    assert yaml.safe_load(path.read_text())["video_memory"]["prune_after_days"] == 30
