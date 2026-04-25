"""TaHiTI hypothesis schema (Pydantic).

Validates the YAML files in hunts/backlog/. Used by:
  - scripts/validate_hypothesis.py (CI / pre-commit)
  - the /hunt skill (Claude reads this to know required fields)
"""
from __future__ import annotations

import re
from datetime import date as _date
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


HYPOTHESIS_ID_RE = re.compile(r"^H-\d{4}-\d{3}$")
ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    INCONCLUSIVE = "inconclusive"
    DROPPED = "dropped"


class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CTISourceType(str, Enum):
    MITRE = "mitre"
    CISA = "cisa"
    VENDOR = "vendor"
    MISP = "misp"   # placeholder for Phase 2


class AttackMapping(BaseModel):
    techniques: list[str] = Field(min_length=1)
    tactics: list[str] = Field(default_factory=list)

    @field_validator("techniques")
    @classmethod
    def _technique_format(cls, v: list[str]) -> list[str]:
        for t in v:
            if not ATTACK_TECHNIQUE_RE.match(t):
                raise ValueError(f"invalid ATT&CK technique id: {t!r} (expected like T1071 or T1071.001)")
        return v


class CTISource(BaseModel):
    type: CTISourceType
    ref: str
    url: Optional[HttpUrl] = None
    date: Optional[_date] = None


class Scope(BaseModel):
    time_range: str
    agents: str | list[str]
    exclude: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    id: str
    title: str
    created: _date
    updated: _date
    owner: str
    status: HypothesisStatus
    priority: Priority

    threat_actor: Optional[str] = None
    attack: AttackMapping
    cti_sources: list[CTISource] = Field(min_length=1)

    abstract: str
    hypothesis: str
    data_sources: list[str] = Field(min_length=1)
    scope: Scope
    success_criteria: str
    investigation_steps: list[str] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not HYPOTHESIS_ID_RE.match(v):
            raise ValueError(f"hypothesis id must match H-YYYY-NNN, got {v!r}")
        return v
