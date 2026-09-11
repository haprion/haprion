"""Let the queue carry the three certificate operations, which have no cluster.

Revision ID: 0024
Revises: 0023
"""

from __future__ import annotations

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

#
# Certificate operations are scoped by certificate, not by cluster, and the
# registry is what says so. Two entries in it settle the question:
#
#   - a certificate published only to receivers names no cluster at all. A row
#     for it has no cluster to put in the column.
#   - a wildcard serving two clusters names both. The column holds one value, so
#     any single cluster written there would be half the truth - and
#     `job_one_active_per_cluster` would serialise the certificate against
#     whichever half was named, while leaving the other free.
#
# So the column becomes optional and the constraint below says which operations
# may leave it out. The publisher already serialises certificate work with one
# `flock` across every certificate rather than per cluster, and the partial
# index here is that same rule expressed in the queue: at most one certificate
# job in flight, whichever certificate it is for.
#


def upgrade() -> None:
    op.execute("""
    alter table job alter column cluster drop not null;

    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish', 'cert_issue', 'cert_publish',
                             'cert_target'));

    --
    -- The shape check has to tolerate the absence it used to forbid. It still
    -- says what a cluster ID looks like when there is one.
    --
    alter table job drop constraint job_cluster_shape;
    alter table job add constraint job_cluster_shape
        check (cluster is null or cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$');

    --
    -- Which operations may omit it, as an equality rather than two one-way
    -- rules: a cluster operation without a cluster and a certificate operation
    -- with one are both refused. Written this way so adding an operation to the
    -- whitelist without deciding its scope fails here rather than queueing a row
    -- whose cluster column means nothing.
    --
    alter table job add constraint job_cluster_presence
        check ((operation in ('cert_issue', 'cert_publish', 'cert_target'))
               = (cluster is null));

    --
    -- At most one certificate job in flight. `(true)` as the indexed expression
    -- is the honest spelling of "there is no key here, only a count of one":
    -- every unfinished certificate row collides with every other, whatever
    -- certificate each is for. The alternative - a unique index on the payload's
    -- certificate ID - would let an issue and a publish for two different
    -- certificates run at once, and they would then meet inside the publisher's
    -- single lock with one of them holding a job lease while it waited.
    --
    create unique index job_one_active_certificate on job ((true))
        where cluster is null and state in ('pending', 'running');
    """)


def downgrade() -> None:
    #
    # Fails where a certificate job exists, and should, for the reason 0016
    # gives: narrowing the set is not worth deleting recorded work over. The
    # not-null restore fails on exactly the same rows, so the first statement
    # that speaks is the one naming the constraint a reader can look up.
    #
    op.execute("""
    drop index job_one_active_certificate;
    alter table job drop constraint job_cluster_presence;

    alter table job drop constraint job_operation_allowed;
    alter table job add constraint job_operation_allowed
        check (operation in ('deploy', 'cert_deploy', 'revert', 'network_publish',
                             'objects_publish'));

    alter table job drop constraint job_cluster_shape;
    alter table job add constraint job_cluster_shape
        check (cluster ~ '^[a-z0-9][a-z0-9_-]{0,31}$');

    alter table job alter column cluster set not null;
    """)
