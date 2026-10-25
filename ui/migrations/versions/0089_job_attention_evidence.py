"""The jobs Needs attention reads, as one set the pruning keeps (review 26-10-24, 05-01).

A failed, refused, partial or unanswered job is a row under Needs attention
until the same step on the same thing works again. That is read from the
newest finished job per cluster, step and subject - and the nightly pruning
removed jobs older than a week once twenty newer ones existed, while the page
read only the newest 200. A failure nothing had settled left the list, and
`/status/attention.json` with it, with nothing having worked.

`job_attention_evidence()` names those jobs: for each cluster, step and
subject, the newest job that finished a run. The pruning keeps them, and
the web reads them beside its recent jobs. It is the interface's own reading
in SQL - `ran`, `step_states`, `ending_step` and `subject` in `jobs.py` - and
the database suite holds the two to the same answer.

Revision ID: 0089
Revises: 0088
"""

from __future__ import annotations

from alembic import op

revision = "0089"
down_revision = "0088"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds one function; a UI from before never calls it"


def upgrade() -> None:
    op.execute("""
    create function job_attention_evidence() returns setof bigint
    language sql stable as $$
        with ran as (
            select id, cluster, operation, state, created_at,
                   --
                   -- `ending_step`: the deploy a Publish & deploy or a node
                   -- change ran after its own step, when its answer is there.
                   --
                   case
                       when operation in ('changes_publish', 'cluster_node')
                        and payload->'deploy' = 'true'::jsonb
                        and jsonb_typeof(
                                result->(case operation
                                             when 'changes_publish' then 'publish'
                                             else 'node' end)) = 'object'
                       then case
                                when jsonb_typeof(result->'step') = 'string'
                                 and result->>'step' in ('deploy', 'cert_deploy')
                                then result->>'step'
                                when jsonb_typeof(result->'operation') = 'string'
                                 and result->>'operation' = 'cert_deploy_cluster'
                                then 'cert_deploy'
                                else 'deploy'
                            end
                       else operation
                   end as ending,
                   --
                   -- `SUBJECT_FIELDS`: what the operation acted on inside its
                   -- cluster; any other operation is about the cluster itself.
                   --
                   case operation
                       when 'cert_issue' then payload->'domain'
                       when 'cert_scep' then payload->'id'
                       when 'cert_import' then payload->'id'
                       when 'cert_request' then payload->'id'
                       when 'cert_receiver' then payload->'receiver'
                       when 'cert_publish' then payload->'certificates'
                       when 'cert_target' then payload->'certificates'
                       when 'cert_delete' then payload->'certificates'
                       when 'server_state' then payload->'object'
                       when 'dynamic_unblock' then payload->'object'
                   end as named
              from job
             where state not in ('pending', 'running')
               --
               -- `coalesce`: a refusal with no error in its result is a run,
               -- and `not` over the null the test gives it would drop it.
               --
               and not coalesce(state = 'blocked'
                                and jsonb_typeof(result->'error'->'code') = 'string'
                                and result->'error'->>'code' = 'held_discarded', false)
        ),
        subjects as (
            select id, cluster, operation, ending, created_at,
                   case jsonb_typeof(named)
                       when 'string' then named #>> '{}'
                       when 'array' then
                           case when exists (select 1 from jsonb_array_elements(named) as item
                                              where jsonb_typeof(item) <> 'string')
                                then ''
                                else coalesce((select string_agg(item #>> '{}', ','
                                                                 order by item #>> '{}' collate "C")
                                                 from jsonb_array_elements(named) as item), '')
                           end
                       else ''
                   end as subject
              from ran
        ),
        steps as (
            select id, cluster, operation as step, subject, created_at from subjects
            union all
            select id, cluster, ending, subject, created_at from subjects
             where ending <> operation
        )
        select distinct on (cluster, step, subject) id
          from steps
         order by cluster, step, subject, created_at desc, id desc
    $$;

    revoke all on function job_attention_evidence() from public;
    grant execute on function job_attention_evidence() to app_web;
    """)


def downgrade() -> None:
    op.execute("drop function if exists job_attention_evidence();")
