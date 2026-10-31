"""The traffic log. Its rows carry visitors' addresses."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["traffic"])
