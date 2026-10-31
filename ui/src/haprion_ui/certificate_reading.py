"""What the certificate pages and the API read to judge a request: the registry and the targets on offer.

The pages and `api.certificates` ask the same two questions before they queue
anything - which certificates exist, and which clusters, receivers and
profiles a form may name - so the answers are read here once.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import Request

from haprion_ui import (
    certificate_form,
    certificates,
    db,
    dns_profile_form,
    features,
    ndes_profile_form,
)
from haprion_ui.config import Config
from haprion_ui.reading import CERTIFICATE_SOURCE, read_manager_certificates, read_source


def registry_views(
    request: Request, config: Config
) -> Mapping[str, certificates.RegistryCertificateView]:
    """The registry as the listing draws it, by ID, for the routes that act on a row."""

    clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    overview = certificates.build_certificate_overview(
        clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=config.poller.stale_after,
    )
    if overview.registry is None:
        return {}
    registry = overview.registry
    #
    # The interface's own entry and its waiting request are rows too, for
    # the routes that act on a row by ID - its CSR, its upload, its
    # renewal - though the listing draws them on the settings page.
    #
    extra = tuple(
        view for view in (registry.interface, registry.interface_request) if view is not None
    )
    return {view.identifier: view for view in (*registry.certificates, *extra)}


def certificate_choices(request: Request, config: Config) -> certificate_form.IssueChoices:
    """The targets the form may offer, read the way the listing reads them."""

    clusters, certificate_rows = read_source(request, config, CERTIFICATE_SOURCE)
    overview = certificates.build_certificate_overview(
        clusters,
        certificate_rows,
        manager=read_manager_certificates(request, config),
        stale_after=config.poller.stale_after,
    )
    usable_profiles: tuple[str, ...] = ()
    profiles_required = config.dns_profiles_public_key is not None
    if profiles_required:
        with request.app.state.pool.connection() as connection:
            profile_rows = db.dns_profiles(connection)
            recent = db.profile_jobs(connection, "dns_profile_apply")
        usable_profiles = tuple(
            profile.id
            for profile in profile_rows
            if dns_profile_form.profile_status(
                profile.id, profile.revision, recent, writes=config.management_writes
            ).usable
        )
    usable_ndes: tuple[str, ...] = ()
    if profiles_required:
        with request.app.state.pool.connection() as connection:
            ndes_rows = db.ndes_profiles(connection)
            recent = db.profile_jobs(connection, "ndes_profile_apply")
        usable_ndes = tuple(
            profile.id
            for profile in ndes_rows
            if ndes_profile_form.profile_status(
                profile.id, profile.revision, recent, writes=config.management_writes
            ).usable
        )
    #
    # With receivers switched off (B193) no form offers one and every
    # form refuses one as not registered: the issue, import and upload
    # forms and Publish to... / Remove from... all read this.
    #
    offered = (
        overview.registry.receivers
        if overview.registry is not None and features.is_on(features.CERT_RECEIVERS)
        else ()
    )
    return certificate_form.IssueChoices(
        clusters=tuple(clusters),
        receivers=offered,
        dns_profiles=usable_profiles,
        profiles_required=profiles_required,
        ndes_profiles=usable_ndes,
        http01=certificate_form.http01_offered(),
        receiver_transports={
            row.identifier: row.transport_label for row in overview.registry.receiver_rows
        }
        if overview.registry
        else {},
        registered=tuple(
            entry.identifier
            for entry in (*overview.registry.certificates, overview.registry.interface)
            if entry is not None
        )
        if overview.registry
        else (),
        imported=tuple(
            entry.identifier
            for entry in overview.registry.certificates
            if entry.source_kind == "import" and not entry.placeholder
        )
        if overview.registry
        else (),
        authorities=tuple(
            entry.identifier
            for entry in overview.registry.certificates
            if entry.source_kind == "authority"
        )
        if overview.registry
        else (),
        waiting=tuple(
            entry.identifier for entry in overview.registry.certificates if entry.csr_pending
        )
        if overview.registry
        else (),
        manager=overview.registry.manager if overview.registry else None,
        interface_id=overview.registry.interface.identifier
        if overview.registry and overview.registry.interface
        else None,
        taken=tuple(
            view.identifier
            for view in (
                *overview.registry.certificates,
                overview.registry.interface,
                overview.registry.interface_request,
            )
            if view is not None
        )
        if overview.registry
        else (),
    )
