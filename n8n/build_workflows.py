#!/usr/bin/env python3
"""Builds the importable n8n workflows from the .js sources (lowest node typeVersions for max compatibility).
Run:  python n8n/build_workflows.py [dashboard_base_url]   (default http://host.docker.internal:8080)"""
import json, pathlib, sys
HERE = pathlib.Path(__file__).resolve().parent
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://host.docker.internal:8080"


def code(name, fname, pos, nid):
    return {"parameters": {"jsCode": (HERE / fname).read_text(encoding="utf-8")}, "id": nid, "name": name,
            "type": "n8n-nodes-base.code", "typeVersion": 1, "position": pos}


alert_wf = {
    "name": "NilePay - Alert Response (SOAR)",
    "nodes": [
        {"parameters": {"httpMethod": "POST", "path": "nilepay-alert", "responseMode": "responseNode", "options": {}},
         "id": "np-webhook-0001", "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 1,
         "position": [0, 0], "webhookId": "nilepay-alert-0001"},
        code("Triage & Playbook", "code_triage.js", [260, 0], "np-code-0002"),
        {"parameters": {"respondWith": "json", "responseBody": "={{ JSON.stringify($json.callback) }}", "options": {}},
         "id": "np-respond-0003", "name": "Respond to Webhook", "type": "n8n-nodes-base.respondToWebhook",
         "typeVersion": 1, "position": [520, 0]},
    ],
    "connections": {
        "Webhook": {"main": [[{"node": "Triage & Playbook", "type": "main", "index": 0}]]},
        "Triage & Playbook": {"main": [[{"node": "Respond to Webhook", "type": "main", "index": 0}]]},
    },
    "active": False, "settings": {}, "pinData": {}, "tags": [],
}
action_wf = {
    "name": "NilePay - Execute Approved Action",
    "nodes": [
        {"parameters": {"httpMethod": "POST", "path": "nilepay-action", "responseMode": "responseNode", "options": {}},
         "id": "np-webhook-0201", "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 1,
         "position": [0, 0], "webhookId": "nilepay-action-0001"},
        code("Execute approved action", "code_execute.js", [260, 0], "np-code-0202"),
        {"parameters": {"respondWith": "json", "responseBody": "={{ JSON.stringify($json) }}", "options": {}},
         "id": "np-respond-0203", "name": "Respond to Webhook", "type": "n8n-nodes-base.respondToWebhook",
         "typeVersion": 1, "position": [520, 0]},
    ],
    "connections": {
        "Webhook": {"main": [[{"node": "Execute approved action", "type": "main", "index": 0}]]},
        "Execute approved action": {"main": [[{"node": "Respond to Webhook", "type": "main", "index": 0}]]},
    },
    "active": False, "settings": {}, "pinData": {}, "tags": [],
}
hunt_wf = {
    "name": "NilePay - Threat Hunt Digest",
    "nodes": [
        {"parameters": {"rule": {"interval": [{"field": "minutes", "minutesInterval": 15}]}},
         "id": "np-sched-0101", "name": "Every 15 minutes", "type": "n8n-nodes-base.scheduleTrigger",
         "typeVersion": 1, "position": [0, 0]},
        {"parameters": {"url": BASE + "/api/hunts/run-all", "options": {}},
         "id": "np-http-0102", "name": "Run all hunts", "type": "n8n-nodes-base.httpRequest",
         "typeVersion": 3, "position": [260, 0]},
        code("Hunt digest", "code_digest.js", [520, 0], "np-code-0103"),
    ],
    "connections": {
        "Every 15 minutes": {"main": [[{"node": "Run all hunts", "type": "main", "index": 0}]]},
        "Run all hunts": {"main": [[{"node": "Hunt digest", "type": "main", "index": 0}]]},
    },
    "active": False, "settings": {}, "pinData": {}, "tags": [],
}
(HERE / "workflow_alert_response.json").write_text(json.dumps(alert_wf, indent=2), encoding="utf-8")
(HERE / "workflow_execute_action.json").write_text(json.dumps(action_wf, indent=2), encoding="utf-8")
(HERE / "workflow_hunt_digest.json").write_text(json.dumps(hunt_wf, indent=2), encoding="utf-8")
print("written: workflow_alert_response.json, workflow_execute_action.json, workflow_hunt_digest.json (dashboard base: %s)" % BASE)
