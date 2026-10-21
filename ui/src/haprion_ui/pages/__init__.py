"""The interface's pages, one module per area, behind the feature switches."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from haprion_ui.config import Config
from haprion_ui.pages import backups, first_cluster, profiles, proxies, sign_in, traffic
from haprion_ui.views import hidden_by_a_switch


def build_router(config: Config) -> APIRouter:
    router = APIRouter(dependencies=[Depends(hidden_by_a_switch)])
    router.include_router(proxies.build_router(config))
    router.include_router(traffic.build_router(config))
    router.include_router(profiles.build_router(config))
    router.include_router(backups.build_router(config))
    router.include_router(sign_in.build_router(config))
    router.include_router(first_cluster.build_router(config))
    return router
