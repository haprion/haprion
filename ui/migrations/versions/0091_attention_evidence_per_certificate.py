"""Needs attention's evidence keyed as the interface keys it now (review 26-10-25).

0089 gave the pruning the jobs Needs attention reads, as the interface's own
reading in SQL. Three things it read differently, or that changed since:

- a Publish & deploy whose step after it was a certificate deploy is named by
  its answer's operation, `cert_deploy` - 0089 compared with the request's
  `cert_deploy_cluster`, which no answer carries (07-06);
- an operation on a list of certificates is one question per certificate: keyed
  on the whole list, a deletion of a, b and c that c refused was never settled
  by deleting c alone, and the pruning kept it for ever (2-02);
- a DNS or NDES profile apply is about its profile, so one profile's success
  does not end another's failure (2-02).

The function is replaced; `jobs.keyed_states` is its twin, and the database
suite holds the two to the same answer.

Revision ID: 0091
Revises: 0090
"""

from __future__ import annotations

from alembic import op

revision = "0091"
down_revision = "0090"
branch_labels = None
depends_on = None

ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = (
    "replaces one function with the same name and result; a UI from before reads it the same way"
)


def upgrade() -> None:
    op.execute("""
    create or replace function job_attention_evidence() returns setof bigint
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
                                 and result->>'operation' = 'cert_deploy'
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
                       when 'dns_profile_apply' then payload->'profile'
                       when 'ndes_profile_apply' then payload->'profile'
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
        --
        -- A list of strings, or null for anything else. Taken apart first:
        -- SQL does not promise to test `jsonb_typeof` before an array
        -- function is called on a scalar.
        --
        listed as (
            select ran.*,
                   case when jsonb_typeof(named) = 'array' then named end as list
              from ran
        ),
        lists as (
            select listed.*,
                   coalesce(jsonb_array_length(list) > 0
                            and not exists (select 1 from jsonb_array_elements(list) as element
                                             where jsonb_typeof(element) <> 'string'),
                            false) as of_strings
              from listed
        ),
        --
        -- `subjects`: a string is one subject, a list of strings one per
        -- certificate in it, anything else the cluster itself ('').
        --
        subjects as (
            select id, cluster, operation, ending, created_at, named #>> '{}' as subject
              from lists
             where jsonb_typeof(named) = 'string'
            union all
            select lists.id, lists.cluster, lists.operation, lists.ending, lists.created_at, item
              from lists, jsonb_array_elements_text(lists.list) as item
             where lists.of_strings
            union all
            select id, cluster, operation, ending, created_at, ''
              from lists
             where jsonb_typeof(named) is distinct from 'string' and not of_strings
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
    """)


def downgrade() -> None:
    op.execute("""
    create or replace function job_attention_evidence() returns setof bigint
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

    """)
