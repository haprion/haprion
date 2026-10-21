"""The interface's pages, one module per area, behind the feature switches."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from haprion_ui.config import Config
from haprion_ui.pages import first_cluster
from haprion_ui.views import hidden_by_a_switch


def build_router(config: Config) -> APIRouter:
    router = APIRouter(dependencies=[Depends(hidden_by_a_switch)])
    router.include_router(first_cluster.build_router(config))
    return router
