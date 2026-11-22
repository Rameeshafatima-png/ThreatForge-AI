import ipaddress
import os
import re
import time
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, TypedDict
import operator

import httpx
from langgraph.graph import END, StateGraph


class Evidence(TypedDict):
    source: str
    type: str
    value: str
    provenance: str


class AgentExecution(TypedDict):
    agent: str
    status: Literal["pending", "running", "completed", "skipped", "error"]
    started_at: str | None
    completed_at: str | None
    duration_ms: int | None
    summary: str
    output: dict[str, Any]
    errors: list[str]


class InvestigationState(TypedDict):
    investigation_id: str
    prompt: str
    evidence: Annotated[list[Evidence], operator.add]
    agent_executions: Annotated[list[AgentExecution], operator.add]
    triage: dict[str, Any]
    threat_intelligence: dict[str, Any]
    log_analysis: dict[str, Any]
    correlation: dict[str, Any]
    risk_report: dict[str, Any]
    report_status: str
    network_records: list[dict[str, Any]]
    network_dataset: dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_indicators(prompt: str) -> list[Evidence]:
    evidence: list[Evidence] = []
    seen: set[str] = set()

    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", prompt):
        try:
            ipaddress.ip_address(match)
            if match not in seen:
                evidence.append({
                    "source": "triage",
                    "type": "ipv4",
                    "value": match,
                    "provenance": "Extracted from submitted investigation text",
                })
                seen.add(match)
        except ValueError:
            pass

    for match in re.findall(r"\b[a-fA-F0-9]{64}\b", prompt):
        if match not in seen:
            evidence.append({
                "source": "triage",
                "type": "sha256",
                "value": match,
                "provenance": "Extracted from submitted investigation text",
            })
            seen.add(match)

    url_match = re.search(r"https?://[^\s]+", prompt, re.IGNORECASE)
    if url_match:
        evidence.append({
            "source": "triage",
            "type": "url",
            "value": url_match.group(0),
            "provenance": "Extracted from submitted investigation text",
        })

    return evidence


def agent_record(
    agent: str,
    status: Literal["pending", "running", "completed", "skipped", "error"],
    started_at: str | None,
    completed_at: str | None,
    duration_ms: int | None,
    summary: str,
    output: dict[str, Any],
    errors: list[str] | None = None,
) -> AgentExecution:
    return {
        "agent": agent,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "summary": summary,
        "output": output,
        "errors": errors or [],
    }


def triage_agent(state: InvestigationState) -> dict[str, Any]:
    started = utc_now()
    start_ms = time.monotonic()
    network_records = state.get("network_records", [])
    if not state["prompt"].strip() and not network_records:
        raise ValueError("Investigation input is empty")

    indicators = extract_indicators(state["prompt"])
    has_security_log = any(
        token in state["prompt"].lower()
        for token in ("log", "event", "authentication", "failed", "login", "response", "source_ip")
    )
    network_dataset = state.get("network_dataset", {})
    network_dataset = {
        "row_count": network_dataset.get("row_count", len(network_records)),
        "feature_count": network_dataset.get("feature_count", len(network_records[0]) if network_records else 0),
        "feature_columns": [
            column
            for column in network_dataset.get("feature_columns", list(network_records[0].keys()) if network_records else [])
            if column not in {"Label", "ClassLabel"}
        ],
        "missing_value_count": network_dataset.get("missing_value_count", sum(
            1 for record in network_records for value in record.values() if value is None
        )),
    }
    network_present = len(network_records) > 0
    plan = {
        "indicators": indicators,
        "indicator_count": len(indicators),
        "security_logs_present": has_security_log,
        "network_flow_records_present": network_present,
        "network_flow_count": len(network_records),
        "network_feature_count": network_dataset.get("feature_count", 0),
        "network_missing_value_count": network_dataset.get("missing_value_count", 0),
        "analysis_plan": [
            "Triage extracted indicators",
            "Run threat intelligence checks when credentials are available",
            "Analyze security log text when present",
            "Analyze bounded network-flow records when present",
        ],
    }
    elapsed = round((time.monotonic() - start_ms) * 1000)
    return {
        "evidence": indicators,
        "triage": plan,
        "report_status": "in_progress",
        "network_dataset": network_dataset,
        "agent_executions": [
            agent_record(
                "Triage Agent",
                "completed",
                started,
                utc_now(),
                elapsed,
                f"Extracted {len(indicators)} indicator(s); identified {'security log text' if has_security_log else 'no explicit security log text'}.",
                plan,
            )
        ],
    }


def route_after_triage(state: InvestigationState) -> list[str]:
    routes: list[str] = []
    if state["triage"]["indicator_count"] > 0:
        routes.append("agent_threat_intelligence")
    if state["triage"]["security_logs_present"] or state["triage"].get("network_flow_records_present"):
        routes.append("agent_log_analysis")
    if not routes:
        routes.append("agent_detection")
    return routes


def threat_intelligence_agent(state: InvestigationState) -> dict[str, Any]:
    started = utc_now()
    start_ms = time.monotonic()
    ip_values = [item["value"] for item in state["evidence"] if item["type"] == "ipv4"]
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    vt_key = os.getenv("VT_API_KEY")
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    if not ip_values:
        elapsed = round((time.monotonic() - start_ms) * 1000)
        return {
            "threat_intelligence": {
                "status": "skipped",
                "provider_calls": [],
                "findings": [],
                "missing": ["No IP indicator available for reputation lookup"],
            },
            "agent_executions": [
                agent_record(
                    "Threat Intelligence Agent",
                    "skipped",
                    started,
                    utc_now(),
                    elapsed,
                    "Skipped because no IP indicator was extracted.",
                    {"provider_calls": [], "findings": []},
                    ["No IP indicator available"],
                )
            ],
        }

    if abuse_key:
        for ip in ip_values:
            try:
                response = httpx.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    timeout=10,
                )
                response.raise_for_status()
                data = response.json().get("data", {})
                findings.append({
                    "provider": "AbuseIPDB",
                    "indicator": ip,
                    "source": "live_api",
                    "data": data,
                })
            except httpx.HTTPError as exc:
                errors.append(f"AbuseIPDB lookup failed for {ip}: {exc}")
    elif vt_key:
        for ip in ip_values:
            try:
                response = httpx.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": vt_key},
                    timeout=10,
                )
                response.raise_for_status()
                findings.append({
                    "provider": "VirusTotal",
                    "indicator": ip,
                    "source": "live_api",
                    "data": response.json().get("data", {}),
                })
            except httpx.HTTPError as exc:
                errors.append(f"VirusTotal lookup failed for {ip}: {exc}")
    else:
        errors.append("No threat intelligence credentials configured")

    elapsed = round((time.monotonic() - start_ms) * 1000)
    status = "completed" if findings else "skipped"
    summary = (
        f"Returned {len(findings)} provider finding(s)."
        if findings
        else "No provider lookup was performed because credentials are unavailable or the lookup failed."
    )
    output = {
        "status": status,
        "provider_calls": [
            finding["provider"] for finding in findings
        ],
        "findings": findings,
        "missing": errors,
    }
    return {
        "threat_intelligence": output,
        "agent_executions": [
            agent_record(
                "Threat Intelligence Agent",
                status,
                started,
                utc_now(),
                elapsed,
                summary,
                output,
                errors,
            )
        ],
    }


def log_analysis_agent(state: InvestigationState) -> dict[str, Any]:
    started = utc_now()
    start_ms = time.monotonic()
    prompt = state["prompt"]
    network_records = state.get("network_records", [])
    network_dataset = state.get("network_dataset", {})

    network_summary: dict[str, Any] = {}
    if network_records:
        numeric_summaries: dict[str, dict[str, float]] = {}

        def numeric_values(feature_name: str) -> list[float]:
            values: list[float] = []
            for record in network_records:
                value = record.get(feature_name)
                if value is None:
                    continue
                try:
                    number = float(value)
                    if number == number:
                        values.append(number)
                except (TypeError, ValueError):
                    continue
            return values

        for feature_name in (
            "Flow Duration",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
            "URG Flag Count",
            "Packet Length Mean",
            "Avg Packet Size",
            "Active Mean",
            "Idle Mean",
            "Fwd PSH Flags",
        ):
            values = numeric_values(feature_name)
            if values:
                numeric_summaries[feature_name] = {
                    "min": min(values),
                    "mean": sum(values) / len(values),
                    "max": max(values),
                }

        syn_values = numeric_values("SYN Flag Count")
        packet_rate_values = numeric_values("Flow Packets/s")
        byte_rate_values = numeric_values("Flow Bytes/s")
        network_patterns: list[str] = []
        repeated_bidirectional_flow_count = 0
        for record in network_records:
            try:
                duration = float(record.get("Flow Duration"))
                forward_packets = float(record.get("Total Fwd Packets"))
                backward_packets = float(record.get("Total Backward Packets"))
            except (TypeError, ValueError):
                continue
            if (
                0 < duration <= 15_000_000
                and 10 <= forward_packets <= 40
                and 10 <= backward_packets <= 40
            ):
                repeated_bidirectional_flow_count += 1

        if (
            repeated_bidirectional_flow_count >= 3
            and repeated_bidirectional_flow_count / len(network_records) >= 0.6
        ):
            network_patterns.append(
                "Repeated short-duration bidirectional network-flow pattern"
            )

        network_summary = {
            "status": "completed",
            "record_count": len(network_records),
            "feature_count": network_dataset.get("feature_count", len(network_records[0]) if network_records else 0),
            "missing_value_count": network_dataset.get("missing_value_count", sum(
                1 for record in network_records for value in record.values() if value is None
            )),
            "numeric_summaries": numeric_summaries,
            "patterns": network_patterns,
            "repeated_bidirectional_flow_count": repeated_bidirectional_flow_count,
        }
    timestamp_pattern = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b")
    timestamp_matches = list(timestamp_pattern.finditer(prompt))

    raw_events: list[str] = []
    if network_records:
        raw_events = []
    elif timestamp_matches:
        for index, match in enumerate(timestamp_matches):
            start = match.start()
            end = timestamp_matches[index + 1].start() if index + 1 < len(timestamp_matches) else len(prompt)
            raw_events.append(prompt[start:end].strip())
    else:
        raw_events = [line.strip() for line in prompt.splitlines() if line.strip()]

    events: list[dict[str, Any]] = []
    for raw_event in raw_events:
        cleaned = re.sub(r"\s+", " ", raw_event).strip()
        timestamp_match = timestamp_pattern.search(cleaned)
        timestamp = timestamp_match.group(0).replace("T", " ") if timestamp_match else None
        event_text = timestamp_pattern.sub("", cleaned, count=1).strip() if timestamp_match else cleaned

        source_ip_match = re.search(
            r"\b(?:from|src(?:=|:)?|source_ip(?:=|:)?)\s*(?:=|:)?\s*"
            r"(\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:*]{2,}\:[0-9a-fA-F:.]+\b)",
            event_text,
            re.IGNORECASE,
        )
        source_ip = source_ip_match.group(1) if source_ip_match else None

        host_match = re.match(r"^(\S+)\s+", event_text)
        host = host_match.group(1) if host_match else None
        service_match = re.search(r"\b(sshd|sudo|login|PAM|pam_unix)\b", event_text, re.IGNORECASE)
        service = service_match.group(1).lower() if service_match else None

        outcome = None
        username = None
        failed_match = re.search(
            r"failed (?:password|authentication|login)\s+(?:for\s+(?:invalid user\s+)?)?([A-Za-z0-9_.@-]+)",
            event_text,
            re.IGNORECASE,
        )
        accepted_match = re.search(
            r"accepted (?:password|publickey|keyboard-interactive)\s+for\s+([A-Za-z0-9_.@-]+)",
            event_text,
            re.IGNORECASE,
        )
        session_match = re.search(
            r"session (?:opened|closed)\s+for user\s+([A-Za-z0-9_.@-]+)",
            event_text,
            re.IGNORECASE,
        )

        if failed_match:
            outcome = "failed"
            username = failed_match.group(1)
        elif accepted_match:
            outcome = "accepted"
            username = accepted_match.group(1)
        elif session_match:
            outcome = "session_opened"
            username = session_match.group(1)

        event = {
            "timestamp": timestamp,
            "host": host,
            "service": service,
            "source_ip": source_ip,
            "username": username,
            "outcome": outcome,
            "raw": cleaned,
        }
        events.append(event)

    failed_events = [event for event in events if event["outcome"] == "failed"]
    accepted_events = [event for event in events if event["outcome"] == "accepted"]
    session_events = [event for event in events if event["outcome"] == "session_opened"]

    groups: dict[str, dict[str, Any]] = {}
    for event in events:
        source_ip = event["source_ip"] or "unknown"
        host = event["host"] or "unknown"
        key = f"{source_ip} -> {host}"
        group = groups.setdefault(
            key,
            {
                "source_ip": source_ip,
                "target_host": host,
                "failed_count": 0,
                "accepted_count": 0,
                "session_count": 0,
                "usernames": set(),
                "timestamps": [],
            },
        )
        if event["outcome"] == "failed":
            group["failed_count"] += 1
        elif event["outcome"] == "accepted":
            group["accepted_count"] += 1
        elif event["outcome"] == "session_opened":
            group["session_count"] += 1
        if event["username"]:
            group["usernames"].add(event["username"])
        if event["timestamp"]:
            group["timestamps"].append(event["timestamp"])

    grouped_events = []
    for group in groups.values():
        grouped_events.append({
            **group,
            "usernames": sorted(group["usernames"]),
        })

    anomaly_terms = ("failed", "failure", "denied", "suspicious", "brute force", "unauthorized")
    anomalies = [
        {
            "timestamp": event["timestamp"],
            "host": event["host"],
            "source_ip": event["source_ip"],
            "username": event["username"],
            "matched_terms": [
                term
                for term in anomaly_terms
                if term in event["raw"].lower()
            ],
            "raw": event["raw"],
        }
        for event in failed_events
    ]

    output = {
        "status": "completed",
        "network_summary": network_summary,
        "event_count": len(events),
        "line_count": len(raw_events),
        "failed_attempt_count": len(failed_events),
        "successful_login_count": len(accepted_events),
        "session_event_count": len(session_events),
        "affected_usernames": sorted({
            event["username"] for event in events if event["username"]
        }),
        "source_ips": sorted({
            event["source_ip"] for event in events if event["source_ip"]
        }),
        "target_hosts": sorted({
            event["host"] for event in events if event["host"]
        }),
        "events": events,
        "groups": grouped_events,
        "anomaly_count": len(failed_events),
        "anomalies": anomalies,
        "missing": (
            [] if failed_events or accepted_events or session_events else [
                "No explicit authentication or session events found",
            ]
        ),
    }
    elapsed = round((time.monotonic() - start_ms) * 1000)
    return {
        "log_analysis": output,
        "agent_executions": [
            agent_record(
                "Log Analysis Agent",
                "completed",
                started,
                utc_now(),
                elapsed,
                (
                    f"Analyzed {len(network_records)} bounded network-flow record(s) and identified "
                    f"{len(network_summary.get('patterns', []))} network pattern(s)."
                    if network_records
                    else f"Parsed {len(raw_events)} submitted line(s) and identified {len(failed_events)} failed authentication event(s)."
                ),
                output,
                output["missing"],
            )
        ],
    }


def detection_agent(state: InvestigationState) -> dict[str, Any]:
    started = utc_now()
    start_ms = time.monotonic()
    log_analysis = state["log_analysis"]
    anomaly_count = log_analysis.get("failed_attempt_count", log_analysis.get("anomaly_count", 0))
    failed_count = log_analysis.get("failed_attempt_count", anomaly_count)
    successful_count = log_analysis.get("successful_login_count", 0)
    session_count = log_analysis.get("session_event_count", 0)
    network_summary = log_analysis.get("network_summary", {})
    source_ips = log_analysis.get("source_ips", [])
    target_hosts = log_analysis.get("target_hosts", [])
    affected_usernames = log_analysis.get("affected_usernames", [])
    provider_findings = state["threat_intelligence"].get("findings", [])
    hypotheses: list[dict[str, Any]] = []
    network_patterns = network_summary.get("patterns", [])
    if network_patterns:
        hypotheses.append({
            "pattern": "Potential abnormal network-flow activity",
            "basis": "; ".join(network_patterns),
            "confidence": "moderate",
            "not_confirmed": "Flow statistics indicate suspicious patterns but do not confirm an attack class",
            "record_count": network_summary.get("record_count", 0),
            "missing_value_count": network_summary.get("missing_value_count", 0),
        })

    ssh_brute_force_success = failed_count >= 5 and successful_count >= 1
    if ssh_brute_force_success:
        basis = (
            f"{failed_count} failed SSH authentication attempt(s)"
            f"{' followed by 1 successful login' if successful_count == 1 else f' followed by {successful_count} successful login(s)'}"
        )
        if session_count:
            basis += f" and {session_count} session event(s)"
        hypotheses.append({
            "pattern": "Potential SSH brute-force attack with successful authentication",
            "basis": basis,
            "confidence": "moderate",
            "not_confirmed": "Compromise or unauthorized access is not confirmed by authentication evidence alone",
            "source_ips": source_ips,
            "target_hosts": target_hosts,
            "affected_usernames": affected_usernames,
        })

    if anomaly_count and not ssh_brute_force_success:
        hypotheses.append({
            "pattern": "Repeated or anomalous authentication/security event",
            "basis": f"{anomaly_count} anomaly candidate(s) extracted from submitted text",
            "confidence": "supporting",
        })
    if provider_findings:
        hypotheses.append({
            "pattern": "External reputation signal",
            "basis": f"{len(provider_findings)} live provider finding(s)",
            "confidence": "provider-dependent",
        })

    output = {
        "hypothesis_count": len(hypotheses),
        "hypotheses": hypotheses,
        "missing": [] if hypotheses else ["Insufficient corroborating evidence for a pattern hypothesis"],
    }
    elapsed = round((time.monotonic() - start_ms) * 1000)
    status = "completed"
    summary = (
        f"Correlated {len(hypotheses)} supported hypothesis/hypotheses."
        if hypotheses
        else "Correlation completed; no supported threat pattern was established from the available evidence."
    )
    return {
        "correlation": output,
        "agent_executions": [
            agent_record(
                "Threat Detection & Correlation Agent",
                status,
                started,
                utc_now(),
                elapsed,
                summary,
                output,
                output["missing"],
            )
        ],
    }


def risk_report_agent(state: InvestigationState) -> dict[str, Any]:
    started = utc_now()
    start_ms = time.monotonic()
    evidence_count = len(state["evidence"])
    hypothesis_count = state["correlation"].get("hypothesis_count", 0)
    provider_count = len(state["threat_intelligence"].get("findings", []))
    log_analysis = state["log_analysis"]
    failed_count = log_analysis.get("failed_attempt_count", 0)
    successful_count = log_analysis.get("successful_login_count", 0)
    session_count = log_analysis.get("session_event_count", 0)
    affected_usernames = log_analysis.get("affected_usernames", [])
    source_ips = log_analysis.get("source_ips", [])
    target_hosts = log_analysis.get("target_hosts", [])
    network_summary = log_analysis.get("network_summary", {})
    network_patterns = network_summary.get("patterns", [])
    network_record_count = network_summary.get("record_count", 0)
    network_missing_count = network_summary.get("missing_value_count", 0)
    ssh_brute_force_success = failed_count >= 5 and successful_count >= 1
    uncertainty: list[str] = []

    if evidence_count == 0 and network_record_count == 0:
        uncertainty.append("No indicators were extracted")
    if provider_count == 0:
        uncertainty.append("No live threat intelligence findings")
    if network_record_count == 0 and state["log_analysis"].get("anomaly_count", 0) == 0:
        uncertainty.append("No corroborating security-log anomalies")
    if ssh_brute_force_success:
        uncertainty.append("Authorization and post-login activity are unknown; successful authentication alone does not confirm compromise")

    confidence = (
        "low"
        if hypothesis_count == 0
        else "moderate"
        if ssh_brute_force_success or network_patterns or evidence_count < 2
        else "supporting"
    )
    severity = "unknown"
    if ssh_brute_force_success:
        severity = "high"
    elif hypothesis_count > 0 and not network_patterns:
        severity = "high" if provider_count > 0 and hypothesis_count > 1 else "medium"

    has_authentication_events = any(
        log_analysis.get(key, 0)
        for key in ("failed_attempt_count", "successful_login_count", "session_event_count")
    )
    report = {
        "classification": (
            "Potential SSH brute-force attack with successful authentication"
            if ssh_brute_force_success
            else network_patterns[0]
            if network_patterns
            else "No supported threat pattern identified"
        ),
        "severity": severity,
        "confidence": confidence,
        "hypothesis_count": hypothesis_count,
        "failed_attempt_count": failed_count,
        "successful_login_count": successful_count,
        "session_event_count": session_count,
        "affected_usernames": affected_usernames,
        "source_ips": source_ips,
        "target_hosts": target_hosts,
        "events": log_analysis.get("events", []),
        "groups": log_analysis.get("groups", []),
        "observed_facts": (
            [
                f"{failed_count} failed SSH authentication attempt(s) recorded",
                f"{successful_count} successful SSH login(s) recorded",
                f"{session_count} SSH session event(s) recorded",
            ]
            if ssh_brute_force_success or has_authentication_events
            else [
                f"{network_record_count} network-flow record(s) analyzed",
                f"{len(network_patterns)} evidence-supported network-flow pattern(s) identified",
            ]
            if network_record_count
            else [
            f"{evidence_count} indicator(s) extracted",
            f"{hypothesis_count} correlated hypothesis/hypotheses",
            ]
        ),
        "hypotheses": state["correlation"].get("hypotheses", []),
        "unknowns": [
            "Whether the successful login was authorized",
            "Post-login activity and privilege changes",
            "External threat intelligence reputation",
        ] if ssh_brute_force_success else (
            [
                "Flow features alone do not establish attack intent or attribution",
                "External threat intelligence reputation",
                f"{network_missing_count} missing network-feature value(s)" if network_missing_count else "No missing network-feature values observed",
            ]
            if network_record_count
            else uncertainty
        ),
        "uncertainty": uncertainty,
        "recommendations": [
            (
                "Treat the successful authentication as high-priority and isolate or verify the target host and source activity"
                if ssh_brute_force_success
                else "Review the submitted evidence in the original system context"
            ),
            (
                "Review active sessions, privileged actions and post-login activity for the affected account"
                if ssh_brute_force_success
                else "Preserve source logs and collection timestamps"
            ),
            "Review the submitted evidence in the original system context",
            "Preserve source logs and collection timestamps",
            "Connect configured threat intelligence providers before attribution decisions",
        ],
    }
    elapsed = round((time.monotonic() - start_ms) * 1000)
    return {
        "risk_report": report,
        "report_status": "generated",
        "agent_executions": [
            agent_record(
                "Risk Assessment & Reporting Agent",
                "completed",
                started,
                utc_now(),
                elapsed,
                "Generated an uncertainty-aware report without asserting unsupported severity or attribution.",
                report,
                uncertainty,
            )
        ],
    }


def build_investigation_graph():
    graph = StateGraph(InvestigationState)
    graph.add_node("agent_triage", triage_agent)
    graph.add_node("agent_threat_intelligence", threat_intelligence_agent)
    graph.add_node("agent_log_analysis", log_analysis_agent)
    graph.add_node("agent_detection", detection_agent)
    graph.add_node("agent_risk_report", risk_report_agent)

    graph.set_entry_point("agent_triage")

    def conditional_routes(state: InvestigationState) -> list[str]:
        return route_after_triage(state)

    graph.add_conditional_edges("agent_triage", conditional_routes)
    graph.add_edge("agent_threat_intelligence", "agent_detection")
    graph.add_edge("agent_log_analysis", "agent_detection")
    graph.add_edge("agent_detection", "agent_risk_report")
    graph.add_edge("agent_risk_report", END)
    return graph.compile()
