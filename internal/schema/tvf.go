// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	"strings"
)

// Names of the bounded-window Table-Valued Functions (TVFs) that provide
// partition-prunable alternatives to the three cross-signal and recursive
// companion views when require_partition_filter = true is enabled on the
// underlying otel_spans, otel_logs, or otel_metrics tables.
const (
	GenAILogsTVFName            = "tvf_gen_ai_logs"
	GenAIMetricExemplarsTVFName = "tvf_gen_ai_metric_exemplars"
	GenAIAgentTrajectoryTVFName = "tvf_gen_ai_agent_trajectory"
)

// GenAILogsTVFDDL creates tvf_gen_ai_logs(start_ts TIMESTAMP, end_ts TIMESTAMP):
// the bounded-window Table-Valued Function counterpart of v_gen_ai_logs over
// the half-open window [start_ts, end_ts).
//
// Unlike v_gen_ai_logs, which joins otel_spans_dedup on a per-row correlation
// window (s.start_time BETWEEN l.timestamp - 24h AND l.timestamp + 1h) that
// BigQuery's static partition-filter validator cannot prune when
// otel_spans.require_partition_filter = true, tvf_gen_ai_logs pushes static
// partition bounds into both otel_logs_dedup ([start_ts, end_ts)) and
// otel_spans_dedup ([start_ts - 24h, end_ts + 1h]) while preserving the exact
// per-row correlation window and output schema of v_gen_ai_logs.
const GenAILogsTVFDDL = `
CREATE OR REPLACE TABLE FUNCTION ` + "`%[1]s.%[2]s." + GenAILogsTVFName + "`" + `(start_ts TIMESTAMP, end_ts TIMESTAMP) AS (
` + GenAILogsTVFQuery + `
);
`

// GenAILogsTVFDDLV1 creates tvf_gen_ai_logs(start_ts TIMESTAMP, end_ts TIMESTAMP)
// over the v1-candidate log and span deduplication views, projecting
// l.object_refs in place of dropped l.payload_refs.
var GenAILogsTVFDDLV1 = `
CREATE OR REPLACE TABLE FUNCTION ` + "`%[1]s.%[2]s." + GenAILogsTVFName + "`" + `(start_ts TIMESTAMP, end_ts TIMESTAMP) AS (
` + GenAILogsTVFQueryV1 + `
);
`

// GenAILogsTVFQueryV1 is the SELECT body of tvf_gen_ai_logs for the
// v1-candidate contract. It takes (project, dataset, logs table, spans table)
// via fmt.Sprintf.
var GenAILogsTVFQueryV1 = strings.ReplaceAll(GenAILogsTVFQuery, "l.payload_refs", "l.object_refs")

// GenAILogsTVFQuery is the SELECT body of tvf_gen_ai_logs. It takes
// (project, dataset, logs table, spans table) via fmt.Sprintf.
const GenAILogsTVFQuery = `
SELECT
  l.timestamp,
  l.receive_time,
  l.trace_id,
  l.span_id,
  l.service_name,
  COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) AS event_name,
  l.severity_number,
  l.severity_text,
  COALESCE(JSON_VALUE(l.attributes, '$."gen_ai.operation.name"'), JSON_VALUE(s.attributes, '$."gen_ai.operation.name"')) AS gen_ai_operation_name,
  COALESCE(
    JSON_VALUE(l.attributes, '$."gen_ai.system"'),
    JSON_VALUE(l.attributes, '$."gen_ai.provider.name"'),
    JSON_VALUE(s.attributes, '$."gen_ai.system"'),
    JSON_VALUE(s.attributes, '$."gen_ai.provider.name"')
  ) AS gen_ai_system,
  COALESCE(
    JSON_VALUE(l.attributes, '$."gen_ai.agent.name"'),
    JSON_VALUE(l.attributes, '$."gcp.vertex.agent.name"'),
    JSON_VALUE(s.attributes, '$."gen_ai.agent.name"'),
    JSON_VALUE(s.attributes, '$."gcp.vertex.agent.name"')
  ) AS gen_ai_agent_name,
  COALESCE(
    JSON_VALUE(l.attributes, '$."gcp.vertex.agent.session_id"'),
    JSON_VALUE(l.attributes, '$."gen_ai.conversation.id"'),
    JSON_VALUE(s.attributes, '$."gcp.vertex.agent.session_id"'),
    JSON_VALUE(s.attributes, '$."gen_ai.conversation.id"')
  ) AS adk_session_id,
  COALESCE(JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"'), JSON_VALUE(s.attributes, '$."gcp.vertex.agent.invocation_id"')) AS adk_invocation_id,
  COALESCE(JSON_VALUE(l.attributes, '$."gcp.vertex.agent.event_id"'), JSON_VALUE(s.attributes, '$."gcp.vertex.agent.event_id"')) AS adk_event_id,
  COALESCE(
    JSON_VALUE(l.attributes, '$."user.id"'),
    JSON_VALUE(l.attributes, '$."gen_ai.user.id"'),
    JSON_VALUE(s.attributes, '$."user.id"'),
    JSON_VALUE(s.attributes, '$."gen_ai.user.id"')
  ) AS adk_user_id,
  l.body,
  l.payload_refs,
  l.attributes,
  l.resource,
  l.instrumentation_scope,
  JSON_VALUE(l.attributes, '$."error.type"') AS error_type
FROM ` + "`%[1]s.%[2]s.%[3]s_dedup`" + ` AS l
LEFT JOIN (
  SELECT *
  FROM ` + "`%[1]s.%[2]s.%[4]s_dedup`" + `
  WHERE start_time >= TIMESTAMP_SUB(start_ts, INTERVAL 24 HOUR)
    AND start_time <= TIMESTAMP_ADD(end_ts, INTERVAL 1 HOUR)
) AS s
  ON l.trace_id = s.trace_id
  AND l.span_id = s.span_id
  AND l.service_name IS NOT DISTINCT FROM s.service_name
  AND s.start_time BETWEEN TIMESTAMP_SUB(l.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(l.timestamp, INTERVAL 1 HOUR)
WHERE l.timestamp >= start_ts
  AND l.timestamp < end_ts
  AND (
    COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) LIKE 'gen_ai.%%'
    OR JSON_VALUE(l.attributes, '$."gen_ai.system"') IS NOT NULL
    OR JSON_VALUE(l.attributes, '$."gen_ai.provider.name"') IS NOT NULL
    OR JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
  )
`

// GenAIMetricExemplarsTVFDDL creates
// tvf_gen_ai_metric_exemplars(start_ts TIMESTAMP, end_ts TIMESTAMP): the
// bounded-window Table-Valued Function counterpart of v_gen_ai_metric_exemplars
// over the half-open window [start_ts, end_ts).
const GenAIMetricExemplarsTVFDDL = `
CREATE OR REPLACE TABLE FUNCTION ` + "`%[1]s.%[2]s." + GenAIMetricExemplarsTVFName + "`" + `(start_ts TIMESTAMP, end_ts TIMESTAMP) AS (
` + GenAIMetricExemplarsTVFQuery + `
);
`

// GenAIMetricExemplarsTVFQuery is the SELECT body of
// tvf_gen_ai_metric_exemplars. It takes (project, dataset, spans table) via
// fmt.Sprintf.
const GenAIMetricExemplarsTVFQuery = `
SELECT
  m.timestamp AS metric_timestamp,
  m.service_name,
  m.metric_name,
  m.metric_unit,
  m.metric_type,
  m.gen_ai_operation_name,
  m.gen_ai_system,
  m.gen_ai_request_model,
  m.gen_ai_response_model,
  m.gen_ai_agent_name,
  m.gen_ai_token_type,
  m.gen_ai_token_modality,
  m.error_type AS metric_error_type,
  ex.time AS exemplar_timestamp,
  ex.value_double AS exemplar_value_double,
  ex.value_int64 AS exemplar_value_int64,
  ex.trace_id AS trace_id,
  ex.span_id AS span_id,
  ex.filtered_attributes AS exemplar_filtered_attributes,
  s.start_time AS span_start_time,
  s.end_time AS span_end_time,
  s.duration_nano AS span_duration_nano,
  ROUND(s.duration_nano / 1e6, 3) AS span_duration_ms,
  s.name AS span_name,
  s.status.code AS span_status_code,
  s.status.message AS span_status_message,
  COALESCE(
    JSON_VALUE(s.attributes, '$."gen_ai.agent.name"'),
    JSON_VALUE(s.attributes, '$."gcp.vertex.agent.name"'),
    JSON_VALUE(s.resource.attributes, '$."gen_ai.agent.name"'),
    JSON_VALUE(s.attributes, '$."gen_ai.main_agent.name"'),
    JSON_VALUE(s.resource.attributes, '$."gen_ai.main_agent.name"')
  ) AS span_gen_ai_agent_name,
  JSON_VALUE(s.attributes, '$."gen_ai.tool.name"') AS span_gen_ai_tool_name,
  COALESCE(
    JSON_VALUE(s.attributes, '$."gcp.vertex.agent.session_id"'),
    JSON_VALUE(s.attributes, '$."gen_ai.conversation.id"')
  ) AS adk_session_id,
  JSON_VALUE(s.attributes, '$."error.type"') AS span_error_type
FROM ` + "`%[1]s.%[2]s." + GenAIMetricsViewName + "`" + ` AS m
INNER JOIN UNNEST(m.exemplars) AS ex
  WITH OFFSET AS exemplar_ordinal
LEFT JOIN (
  SELECT *
  FROM ` + "`%[1]s.%[2]s.%[3]s_dedup`" + `
  WHERE start_time >= TIMESTAMP_SUB(start_ts, INTERVAL 24 HOUR)
    AND start_time <= TIMESTAMP_ADD(end_ts, INTERVAL 1 HOUR)
) AS s
  ON s.trace_id = ex.trace_id
  AND s.span_id = ex.span_id
  AND s.service_name IS NOT DISTINCT FROM m.service_name
  AND s.start_time BETWEEN TIMESTAMP_SUB(m.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(m.timestamp, INTERVAL 1 HOUR)
WHERE m.timestamp >= start_ts
  AND m.timestamp < end_ts
  AND ex.trace_id IS NOT NULL
  AND ex.span_id IS NOT NULL
  AND ex.trace_id != ''
  AND ex.span_id != ''
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY m.timestamp, m.time_unix_nano, m.service_name, m.metric_name, m.metric_type, m.point_fingerprint, exemplar_ordinal
  ORDER BY s.end_time DESC, s.start_time DESC, s.receive_time DESC, s.name ASC
) = 1
`

// GenAIAgentTrajectoryTVFDDL creates
// tvf_gen_ai_agent_trajectory(start_ts TIMESTAMP, end_ts TIMESTAMP, context_start_ts TIMESTAMP, context_end_ts TIMESTAMP):
// the caller-bounded context-horizon Table-Valued Function counterpart of
// v_gen_ai_agent_trajectory over the half-open output window [start_ts, end_ts)
// with span context reconstructed over [context_start_ts, context_end_ts).
//
// Like v_gen_ai_agent_trajectory, it avoids BigQuery CTE-inlining blowups by
// packing per-(trace_id, service_name) graph metadata into a compact topo_nodes
// array (single payload-free scan in topo_raw), resolving the 0..16-hop tree
// walk (topo_edges -> topo_walks) and 1..32-hop emitted-ancestor token coverage
// (topo_emitted -> topo_ancestors -> topo_cov -> resolved_topology) via array
// pointer walks before joining back to spans once for payload columns over the
// caller-supplied [context_start_ts, context_end_ts) horizon and filtering
// emitted rows to [start_ts, end_ts). It matches v_gen_ai_agent_trajectory when
// all spans of a trace fall within [context_start_ts, context_end_ts), and
// otherwise computes depth, root_span_id, is_orphan, is_leaf, is_token_leaf,
// and step_index strictly within [context_start_ts, context_end_ts).
const GenAIAgentTrajectoryTVFDDL = `
CREATE OR REPLACE TABLE FUNCTION ` + "`%[1]s.%[2]s." + GenAIAgentTrajectoryTVFName + "`" + `(start_ts TIMESTAMP, end_ts TIMESTAMP, context_start_ts TIMESTAMP, context_end_ts TIMESTAMP) AS (
` + GenAIAgentTrajectoryTVFQuery + `
);
`

// GenAIAgentTrajectoryTVFQuery is the SELECT body of
// tvf_gen_ai_agent_trajectory. It takes (project, dataset) via fmt.Sprintf.
const GenAIAgentTrajectoryTVFQuery = `
WITH
  spans AS (
    SELECT
      start_time,
      end_time,
      duration_nano,
      duration_ms,
      trace_id,
      span_id,
      parent_span_id,
      service_name,
      span_name,
      span_kind,
      status_code,
      status_message,
      gen_ai_operation_name,
      gen_ai_system,
      gen_ai_provider_name,
      gen_ai_request_model,
      gen_ai_response_model,
      gen_ai_agent_id,
      gen_ai_agent_name,
      gen_ai_agent_version,
      gen_ai_main_agent_id,
      gen_ai_main_agent_name,
      gen_ai_tool_name,
      gen_ai_tool_call_id,
      gen_ai_usage_input_tokens,
      gen_ai_usage_output_tokens,
      gen_ai_usage_reasoning_tokens,
      adk_session_id,
      adk_invocation_id,
      adk_user_id,
      error_type,
      COALESCE(
        JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
        JSON_VALUE(attributes, '$."gcp.vertex.agent.name"')
      ) AS declared_agent_name,
      COALESCE(
        JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
        JSON_VALUE(attributes, '$."gcp.vertex.agent.name"'),
        IF(gen_ai_operation_name IN ('invoke_agent', 'create_agent'), gen_ai_agent_name, NULL)
      ) AS agent_path_name
    FROM ` + "`%[1]s.%[2]s." + GenAISpansViewName + "`" + `
    WHERE start_time >= context_start_ts
      AND start_time < context_end_ts
    QUALIFY ROW_NUMBER() OVER (
      PARTITION BY trace_id, service_name, span_id
      ORDER BY start_time ASC, end_time DESC, span_name ASC, duration_nano DESC
    ) = 1
  ),
  topo_raw AS (
    SELECT
      trace_id,
      service_name,
      ARRAY_AGG(
        STRUCT(
          start_time,
          span_id,
          parent_span_id,
          (parent_span_id IS NOT NULL AND parent_span_id != '') AS has_parent_id,
          (gen_ai_operation_name IN ('invoke_agent', 'create_agent')) AS is_agent_op,
          (declared_agent_name IS NOT NULL) AS has_declared_agent,
          COALESCE(declared_agent_name, gen_ai_agent_name) AS resolved_agent_name,
          agent_path_name,
          (gen_ai_usage_input_tokens IS NOT NULL) AS has_in,
          (gen_ai_usage_output_tokens IS NOT NULL) AS has_out,
          (gen_ai_usage_reasoning_tokens IS NOT NULL) AS has_reas
        )
        ORDER BY start_time ASC, span_id ASC
      ) AS topo_nodes
    FROM spans
    GROUP BY trace_id, service_name
  ),
  topo_edges AS (
    SELECT
      g.trace_id,
      g.service_name,
      g.topo_nodes,
      ARRAY(
        SELECT AS STRUCT
          p_idx AS raw_parent_idx,
          IF(
            p_idx IS NOT NULL
              AND p.start_time BETWEEN TIMESTAMP_SUB(n.start_time, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(n.start_time, INTERVAL 1 HOUR),
            p_idx,
            CAST(NULL AS INT64)
          ) AS tree_parent_idx
        FROM UNNEST(g.topo_nodes) AS n
          WITH OFFSET AS n_idx
        LEFT JOIN UNNEST(g.topo_nodes) AS p
          WITH OFFSET AS p_idx
          ON n.has_parent_id
          AND p.span_id = n.parent_span_id
        ORDER BY n_idx ASC
      ) AS edges
    FROM topo_raw AS g
  ),
  topo_walks AS (
    SELECT
      g.trace_id,
      g.service_name,
      g.topo_nodes,
      g.edges,
      ARRAY(
        SELECT AS STRUCT
          ARRAY(
            SELECT anc_idx
            FROM UNNEST([
              n_idx,
              e0.tree_parent_idx,
              e1.tree_parent_idx,
              e2.tree_parent_idx,
              e3.tree_parent_idx,
              e4.tree_parent_idx,
              e5.tree_parent_idx,
              e6.tree_parent_idx,
              e7.tree_parent_idx,
              e8.tree_parent_idx,
              e9.tree_parent_idx,
              e10.tree_parent_idx,
              e11.tree_parent_idx,
              e12.tree_parent_idx,
              e13.tree_parent_idx,
              e14.tree_parent_idx,
              e15.tree_parent_idx
            ]) AS anc_idx
              WITH OFFSET AS hop_ord
            WHERE anc_idx IS NOT NULL
            ORDER BY hop_ord DESC
          ) AS root_to_self,
          IF(
            e16.tree_parent_idx IS NULL,
            (
              SELECT COUNT(anc_idx)
              FROM UNNEST([
                e0.tree_parent_idx,
                e1.tree_parent_idx,
                e2.tree_parent_idx,
                e3.tree_parent_idx,
                e4.tree_parent_idx,
                e5.tree_parent_idx,
                e6.tree_parent_idx,
                e7.tree_parent_idx,
                e8.tree_parent_idx,
                e9.tree_parent_idx,
                e10.tree_parent_idx,
                e11.tree_parent_idx,
                e12.tree_parent_idx,
                e13.tree_parent_idx,
                e14.tree_parent_idx,
                e15.tree_parent_idx
              ]) AS anc_idx
            ),
            17
          ) AS depth
        FROM UNNEST(g.edges) AS e0
          WITH OFFSET AS n_idx
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e0.tree_parent_idx)]]) AS e1 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e1.tree_parent_idx)]]) AS e2 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e2.tree_parent_idx)]]) AS e3 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e3.tree_parent_idx)]]) AS e4 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e4.tree_parent_idx)]]) AS e5 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e5.tree_parent_idx)]]) AS e6 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e6.tree_parent_idx)]]) AS e7 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e7.tree_parent_idx)]]) AS e8 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e8.tree_parent_idx)]]) AS e9 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e9.tree_parent_idx)]]) AS e10 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e10.tree_parent_idx)]]) AS e11 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e11.tree_parent_idx)]]) AS e12 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e12.tree_parent_idx)]]) AS e13 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e13.tree_parent_idx)]]) AS e14 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e14.tree_parent_idx)]]) AS e15 ON TRUE
        LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e15.tree_parent_idx)]]) AS e16 ON TRUE
        ORDER BY n_idx ASC
      ) AS tree_info
    FROM topo_edges AS g
  ),
  topo_emitted AS (
    SELECT
      g.trace_id,
      g.service_name,
      g.topo_nodes,
      g.edges,
      g.tree_info,
      ARRAY(
        SELECT
          IF(
            ti.depth <= 16
              AND e.raw_parent_idx IS NOT NULL
              AND e.raw_parent_idx != n_idx
              AND g.tree_info[SAFE_OFFSET(e.raw_parent_idx)].depth <= 16,
            e.raw_parent_idx,
            CAST(NULL AS INT64)
          )
        FROM UNNEST(g.edges) AS e
          WITH OFFSET AS n_idx
        INNER JOIN UNNEST([g.tree_info[OFFSET(n_idx)]]) AS ti ON TRUE
        ORDER BY n_idx ASC
      ) AS emitted_parent_idxs
    FROM topo_walks AS g
  ),
  topo_ancestors AS (
    SELECT
      g.trace_id,
      g.service_name,
      g.topo_nodes,
      g.edges,
      g.tree_info,
      ARRAY(
        SELECT AS STRUCT
          ARRAY(
            SELECT DISTINCT anc_idx
            FROM UNNEST([
              p1, p2, p3, p4, p5, p6, p7, p8,
              p9, p10, p11, p12, p13, p14, p15, p16,
              p17, p18, p19, p20, p21, p22, p23, p24,
              p25, p26, p27, p28, p29, p30, p31, p32
            ]) AS anc_idx
            WHERE anc_idx IS NOT NULL
              AND anc_idx != n_idx
          ) AS anc_idxs
        FROM UNNEST(g.emitted_parent_idxs) AS p1
          WITH OFFSET AS n_idx
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p1)]]) AS p2 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p2)]]) AS p3 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p3)]]) AS p4 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p4)]]) AS p5 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p5)]]) AS p6 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p6)]]) AS p7 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p7)]]) AS p8 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p8)]]) AS p9 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p9)]]) AS p10 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p10)]]) AS p11 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p11)]]) AS p12 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p12)]]) AS p13 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p13)]]) AS p14 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p14)]]) AS p15 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p15)]]) AS p16 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p16)]]) AS p17 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p17)]]) AS p18 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p18)]]) AS p19 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p19)]]) AS p20 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p20)]]) AS p21 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p21)]]) AS p22 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p22)]]) AS p23 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p23)]]) AS p24 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p24)]]) AS p25 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p25)]]) AS p26 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p26)]]) AS p27 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p27)]]) AS p28 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p28)]]) AS p29 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p29)]]) AS p30 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p30)]]) AS p31 ON TRUE
        LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p31)]]) AS p32 ON TRUE
        ORDER BY n_idx ASC
      ) AS emitted_ancs
    FROM topo_emitted AS g
  ),
  topo_cov AS (
    SELECT
      g.trace_id,
      g.service_name,
      g.topo_nodes,
      g.edges,
      g.tree_info,
      ARRAY(
        SELECT AS STRUCT
          anc_idx,
          LOGICAL_OR(d_node.has_in) AS has_input,
          LOGICAL_OR(d_node.has_out) AS has_output,
          LOGICAL_OR(d_node.has_reas) AS has_reasoning
        FROM UNNEST(g.emitted_ancs) AS d_anc
          WITH OFFSET AS d_idx
        INNER JOIN UNNEST([g.topo_nodes[OFFSET(d_idx)]]) AS d_node ON TRUE
        INNER JOIN UNNEST(d_anc.anc_idxs) AS anc_idx
        INNER JOIN UNNEST([g.topo_nodes[OFFSET(anc_idx)]]) AS a_node ON TRUE
        WHERE (d_node.has_in OR d_node.has_out OR d_node.has_reas)
          AND (
            d_idx NOT IN UNNEST(g.emitted_ancs[OFFSET(anc_idx)].anc_idxs)
            OR d_node.start_time > a_node.start_time
            OR (d_node.start_time = a_node.start_time AND d_node.span_id > a_node.span_id)
          )
        GROUP BY anc_idx
      ) AS cov_rows
    FROM topo_ancestors AS g
  ),
  resolved_topology AS (
    SELECT
      g.trace_id,
      g.service_name,
      n.span_id,
      ti.depth,
      g.topo_nodes[OFFSET(ti.root_to_self[OFFSET(0)])].span_id AS root_span_id,
      COALESCE(
        (
          SELECT g.topo_nodes[OFFSET(p_idx)].span_id
          FROM UNNEST(ti.root_to_self) AS p_idx
            WITH OFFSET AS pos
          WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
          ORDER BY pos DESC
          LIMIT 1
        ),
        (
          SELECT g.topo_nodes[OFFSET(p_idx)].span_id
          FROM UNNEST(ti.root_to_self) AS p_idx
            WITH OFFSET AS pos
          WHERE g.topo_nodes[OFFSET(p_idx)].has_declared_agent
          ORDER BY pos ASC
          LIMIT 1
        )
      ) AS nearest_agent_span_id,
      IF(
        EXISTS (
          SELECT 1
          FROM UNNEST(ti.root_to_self) AS p_idx
          WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
        ),
        (
          SELECT g.topo_nodes[OFFSET(p_idx)].resolved_agent_name
          FROM UNNEST(ti.root_to_self) AS p_idx
            WITH OFFSET AS pos
          WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
          ORDER BY pos DESC
          LIMIT 1
        ),
        (
          SELECT g.topo_nodes[OFFSET(p_idx)].resolved_agent_name
          FROM UNNEST(ti.root_to_self) AS p_idx
            WITH OFFSET AS pos
          WHERE g.topo_nodes[OFFSET(p_idx)].has_declared_agent
          ORDER BY pos ASC
          LIMIT 1
        )
      ) AS nearest_agent_name,
      ARRAY(
        SELECT g.topo_nodes[OFFSET(p_idx)].agent_path_name
        FROM UNNEST(ti.root_to_self) AS p_idx
          WITH OFFSET AS pos
        WHERE g.topo_nodes[OFFSET(p_idx)].agent_path_name IS NOT NULL
          AND (
            pos = 0
            OR g.topo_nodes[OFFSET(p_idx)].agent_path_name IS DISTINCT FROM (
              SELECT g.topo_nodes[OFFSET(prev_idx)].agent_path_name
              FROM UNNEST(ti.root_to_self) AS prev_idx
                WITH OFFSET AS prev_pos
              WHERE prev_pos < pos
                AND g.topo_nodes[OFFSET(prev_idx)].agent_path_name IS NOT NULL
              ORDER BY prev_pos DESC
              LIMIT 1
            )
          )
        ORDER BY pos ASC
      ) AS agent_path,
      g.topo_nodes[OFFSET(ti.root_to_self[OFFSET(0)])].has_parent_id AS is_orphan,
      ROW_NUMBER() OVER (
        PARTITION BY g.trace_id, g.service_name
        ORDER BY n.start_time ASC, n.span_id ASC
      ) AS step_index,
      IF(
        EXISTS (
          SELECT 1
          FROM UNNEST(g.edges) AS ce
          WHERE ce.raw_parent_idx = n_idx
        ),
        n.span_id,
        CAST(NULL AS STRING)
      ) AS leaf_parent_span_id,
      COALESCE(cov.has_input, FALSE) AS cov_has_input,
      COALESCE(cov.has_output, FALSE) AS cov_has_output,
      COALESCE(cov.has_reasoning, FALSE) AS cov_has_reasoning
    FROM topo_cov AS g
    INNER JOIN UNNEST(g.topo_nodes) AS n
      WITH OFFSET AS n_idx
    INNER JOIN UNNEST([g.tree_info[OFFSET(n_idx)]]) AS ti ON TRUE
    LEFT JOIN UNNEST(g.cov_rows) AS cov
      ON cov.anc_idx = n_idx
    WHERE ti.depth <= 16
  ),
  trajectory AS (
    SELECT
      s.start_time,
      s.end_time,
      s.duration_nano,
      s.duration_ms,
      s.trace_id,
      s.span_id,
      s.parent_span_id,
      s.service_name,
      s.span_name,
      s.span_kind,
      s.status_code,
      s.status_message,
      s.gen_ai_operation_name,
      s.gen_ai_system,
      s.gen_ai_provider_name,
      s.gen_ai_request_model,
      s.gen_ai_response_model,
      s.gen_ai_agent_id,
      s.gen_ai_agent_name,
      s.gen_ai_agent_version,
      s.gen_ai_main_agent_id,
      s.gen_ai_main_agent_name,
      s.gen_ai_tool_name,
      s.gen_ai_tool_call_id,
      s.gen_ai_usage_input_tokens,
      s.gen_ai_usage_output_tokens,
      s.gen_ai_usage_reasoning_tokens,
      s.adk_session_id,
      s.adk_invocation_id,
      s.adk_user_id,
      s.error_type,
      r.depth,
      r.root_span_id,
      r.nearest_agent_span_id,
      r.nearest_agent_name,
      r.agent_path,
      r.is_orphan,
      r.step_index,
      r.leaf_parent_span_id,
      r.cov_has_input,
      r.cov_has_output,
      r.cov_has_reasoning
    FROM resolved_topology AS r
    INNER JOIN spans AS s
      ON s.trace_id = r.trace_id
      AND s.span_id = r.span_id
      AND s.service_name IS NOT DISTINCT FROM r.service_name
  )
SELECT
  t.start_time,
  t.end_time,
  t.duration_nano,
  t.duration_ms,
  t.trace_id,
  t.span_id,
  t.parent_span_id,
  t.service_name,
  t.span_name,
  t.span_kind,
  t.status_code,
  t.status_message,
  t.gen_ai_operation_name,
  t.gen_ai_system,
  t.gen_ai_provider_name,
  t.gen_ai_request_model,
  t.gen_ai_response_model,
  t.gen_ai_agent_id,
  t.gen_ai_agent_name,
  t.gen_ai_agent_version,
  t.gen_ai_main_agent_id,
  t.gen_ai_main_agent_name,
  t.gen_ai_tool_name,
  t.gen_ai_tool_call_id,
  IF(
    COALESCE(token_leaf_check.has_input, FALSE)
    AND (
      (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
      OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
    ),
    CAST(NULL AS INT64),
    t.gen_ai_usage_input_tokens
  ) AS gen_ai_usage_input_tokens,
  IF(
    COALESCE(token_leaf_check.has_output, FALSE)
    AND (
      (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
      OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
    ),
    CAST(NULL AS INT64),
    t.gen_ai_usage_output_tokens
  ) AS gen_ai_usage_output_tokens,
  IF(
    COALESCE(token_leaf_check.has_reasoning, FALSE)
    AND (
      (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
      OR (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
    ),
    CAST(NULL AS INT64),
    t.gen_ai_usage_reasoning_tokens
  ) AS gen_ai_usage_reasoning_tokens,
  t.adk_session_id,
  t.adk_invocation_id,
  t.adk_user_id,
  t.error_type,
  t.depth,
  t.root_span_id,
  t.nearest_agent_span_id,
  t.nearest_agent_name,
  t.agent_path,
  t.is_orphan,
  t.step_index,
  (leaf_check.span_id IS NULL) AS is_leaf,
  (
    (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
    OR (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
    OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
  ) AS is_token_leaf
FROM trajectory AS t
LEFT JOIN UNNEST([STRUCT(t.leaf_parent_span_id AS span_id)]) AS leaf_check
  ON leaf_check.span_id IS NOT NULL
LEFT JOIN UNNEST([
  STRUCT(
    t.cov_has_input AS has_input,
    t.cov_has_output AS has_output,
    t.cov_has_reasoning AS has_reasoning
  )
]) AS token_leaf_check
  ON TRUE
WHERE t.start_time >= start_ts
  AND t.start_time < end_ts
`

// CompanionTVFDDLs returns the CREATE OR REPLACE TABLE FUNCTION statements for
// all three bounded-window companion TVFs (tvf_gen_ai_logs,
// tvf_gen_ai_metric_exemplars, tvf_gen_ai_agent_trajectory), keyed by routine
// name, for the default v0alpha2 contract.
func CompanionTVFDDLs(project, dataset, spansTable, logsTable string) map[string]string {
	return CompanionTVFDDLsForContract(ContractV0Alpha2, project, dataset, spansTable, logsTable)
}

// CompanionTVFDDLsForContract returns the CREATE OR REPLACE TABLE FUNCTION
// statements for all three bounded-window companion TVFs under contract c, keyed
// by routine name.
func CompanionTVFDDLsForContract(c Contract, project, dataset, spansTable, logsTable string) map[string]string {
	logsDDL := GenAILogsTVFDDL
	if c == ContractV1Candidate {
		logsDDL = GenAILogsTVFDDLV1
	}
	return map[string]string{
		GenAILogsTVFName:            strings.TrimSpace(fmt.Sprintf(logsDDL, project, dataset, logsTable, spansTable)),
		GenAIMetricExemplarsTVFName: strings.TrimSpace(fmt.Sprintf(GenAIMetricExemplarsTVFDDL, project, dataset, spansTable)),
		GenAIAgentTrajectoryTVFName: strings.TrimSpace(fmt.Sprintf(GenAIAgentTrajectoryTVFDDL, project, dataset)),
	}
}

// CompanionTVFQueries returns the SELECT body for all three bounded-window
// companion TVFs, keyed by routine name, for the default v0alpha2 contract.
func CompanionTVFQueries(project, dataset, spansTable, logsTable string) map[string]string {
	return CompanionTVFQueriesForContract(ContractV0Alpha2, project, dataset, spansTable, logsTable)
}

// CompanionTVFQueriesForContract returns the SELECT body for all three
// bounded-window companion TVFs under contract c, keyed by routine name.
func CompanionTVFQueriesForContract(c Contract, project, dataset, spansTable, logsTable string) map[string]string {
	logsQuery := GenAILogsTVFQuery
	if c == ContractV1Candidate {
		logsQuery = GenAILogsTVFQueryV1
	}
	return map[string]string{
		GenAILogsTVFName:            strings.TrimSpace(fmt.Sprintf(logsQuery, project, dataset, logsTable, spansTable)),
		GenAIMetricExemplarsTVFName: strings.TrimSpace(fmt.Sprintf(GenAIMetricExemplarsTVFQuery, project, dataset, spansTable)),
		GenAIAgentTrajectoryTVFName: strings.TrimSpace(fmt.Sprintf(GenAIAgentTrajectoryTVFQuery, project, dataset)),
	}
}
