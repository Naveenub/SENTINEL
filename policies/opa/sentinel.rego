# L2 policy for SENTINEL when SENTINEL_POLICY_BACKEND=opa.
# Input:  {agent, tool, args, hosts}   (hosts = parsed from URLs in args)
# Output: data.sentinel.authz.decision = {effect: allow|deny|approve, reason}
# YAML (policies/agents.yaml) still defines each tool's schema/sandbox/secrets/rate limit.
# Deny by default: no grant in data.json, no call.
package sentinel.authz

import rego.v1

default decision := {"effect": "deny", "reason": "no grant for this agent/tool"}

grant := data.grants[input.agent][input.tool]

host_ok(h) if {
	some pattern in grant.hosts
	glob.match(pattern, ["."], lower(h))
}

deny contains sprintf("host not allowed: %s", [h]) if {
	grant.hosts
	some h in input.hosts
	not host_ok(h)
}

# Rules YAML cannot express: inspect argument content.
deny contains "recursive delete is never allowed" if {
	input.tool == "shell"
	regex.match(`\brm\s+(-\w*\s+)*-\w*[rR]`, input.args.cmd)
}

decision := {"effect": "deny", "reason": concat("; ", sort(deny))} if {
	grant
	count(deny) > 0
}

decision := {"effect": "approve", "reason": "opa: approval required"} if {
	grant
	count(deny) == 0
	grant.approval == true
}

decision := {"effect": "allow", "reason": "opa: granted"} if {
	grant
	count(deny) == 0
	not grant.approval
}
