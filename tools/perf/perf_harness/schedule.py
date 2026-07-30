"""Deterministic reference/candidate scheduling."""

from __future__ import annotations

from typing import Any, Iterable


def abba_variants(repetitions_per_variant: int) -> list[str]:
    """Return exact ABBA cycles with equal samples for both variants."""
    if repetitions_per_variant < 2 or repetitions_per_variant % 2:
        raise ValueError("ABBA repetitions must be an even integer of at least 2")
    return ["reference", "candidate", "candidate", "reference"] * (
        repetitions_per_variant // 2
    )


def warmup_variants(warmups_per_variant: int) -> list[str]:
    """Alternate warmups while reversing each pair to limit order bias."""
    if warmups_per_variant < 0:
        raise ValueError("warmups must be non-negative")
    variants: list[str] = []
    for index in range(warmups_per_variant):
        variants.extend(
            ("reference", "candidate")
            if index % 2 == 0
            else ("candidate", "reference")
        )
    return variants


def build_schedule(workloads: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    schedule: list[dict[str, Any]] = []
    global_index = 0
    for workload in workloads:
        phase_variants = (
            ("warmup", warmup_variants(workload["warmups"])),
            ("measure", abba_variants(workload["repetitions"])),
        )
        for phase, variants in phase_variants:
            for phase_index, variant in enumerate(variants):
                slot_id = (
                    f"{workload['id']}:{phase}:{phase_index:03d}:{variant}"
                )
                schedule.append(
                    {
                        "slot_id": slot_id,
                        "order_index": global_index,
                        "phase": phase,
                        "phase_index": phase_index,
                        "variant": variant,
                        "suite_id": workload["suite_id"],
                        "workload_id": workload["id"],
                    }
                )
                global_index += 1
    return schedule


def remaining_slots(
    schedule: Iterable[dict[str, Any]], samples: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    terminal = {"success", "error", "timeout", "blocked"}
    completed = {
        sample.get("slot_id")
        for sample in samples
        if sample.get("status") in terminal
    }
    return [slot for slot in schedule if slot["slot_id"] not in completed]

