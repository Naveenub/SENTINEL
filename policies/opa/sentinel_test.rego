package sentinel.authz_test

import rego.v1

import data.sentinel.authz

test_ungranted_tool_denied if {
	authz.decision.effect == "deny" with input as {"agent": "research-bot", "tool": "rm_rf", "args": {}, "hosts": []}
}

test_unknown_agent_denied if {
	authz.decision.effect == "deny" with input as {"agent": "ghost", "tool": "web_fetch", "args": {}, "hosts": []}
}

test_granted_tool_allowed if {
	authz.decision.effect == "allow" with input as {"agent": "research-bot", "tool": "web_fetch", "args": {"url": "https://a.test"}, "hosts": ["a.test"]}
}

test_shell_needs_approval if {
	authz.decision.effect == "approve" with input as {"agent": "research-bot", "tool": "shell", "args": {"cmd": "ls"}, "hosts": []}
}

test_recursive_delete_denied_even_with_approval_grant if {
	d := authz.decision with input as {"agent": "research-bot", "tool": "shell", "args": {"cmd": "rm -rf /"}, "hosts": []}
	d.effect == "deny"
	contains(d.reason, "recursive delete")
}

test_host_allowlist if {
	authz.decision.effect == "allow" with input as {"agent": "research-bot", "tool": "fetch_docs", "args": {}, "hosts": ["api.github.com"]}
	authz.decision.effect == "deny" with input as {"agent": "research-bot", "tool": "fetch_docs", "args": {}, "hosts": ["evil.test"]}
	authz.decision.effect == "deny" with input as {"agent": "research-bot", "tool": "fetch_docs", "args": {}, "hosts": ["github.com"]}
}
