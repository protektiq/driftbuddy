package Cx

import data.generic.ansible as ans_lib
import data.generic.common as common_lib

CxPolicy[result] {
	task := ans_lib.tasks[_][t]
	modulesFirewall := {"google.cloud.gcp_compute_firewall", "gcp_compute_firewall"}
	firewall := task[modulesFirewall[_]]
	ans_lib.checkState(firewall)

	contains(firewall.name, "default")

	tk := ans_lib.tasks[id][_]
	modulesCompute := {"google.cloud.gcp_compute_network", "gcp_compute_network"}
	computeNetwork := tk[modulesCompute[m]]
	ans_lib.checkState(computeNetwork)
	firewall.network == sprintf("{{ %s }}", [tk.register])


	result := {
		"documentId": id,
		"resourceType": modulesCompute[m],
		"resourceName": tk.name,
		"searchKey": sprintf("name={{%s}}.{{%s}}", [tk.name, modulesCompute[m]]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'%s' should not be using a default firewall rule", [modulesCompute[m]]),
		"keyActualValue": sprintf("'%s' is using a default firewall rule", [modulesCompute[m]]),
		"searchLine": common_lib.build_search_line(["playbooks", t, modulesCompute[m]], []),
	}
}
