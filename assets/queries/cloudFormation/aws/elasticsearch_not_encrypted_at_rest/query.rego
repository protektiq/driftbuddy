package Cx

import data.generic.common as common_lib
import data.generic.cloudformation as cf_lib

CxPolicy[result] {
	docs := input.document[i]
	[path, Resources] := walk(docs)
	resource := Resources[name]
	resource.Type == "AWS::Elasticsearch::Domain"
	properties := resource.Properties

	not common_lib.valid_key(properties, "EncryptionAtRestOptions")

	result := {
		"documentId": input.document[i].id,
		"resourceType": resource.Type,
		"resourceName": cf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s%s.Properties", [cf_lib.getPath(path),name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("Resources.%s.Properties.EncryptionAtRestOptions should be defined and not null", [name]),
		"keyActualValue": sprintf("Resources.%s.Properties.EncryptionAtRestOptions is undefined or null", [name]),
	}
}

CxPolicy[result] {
	docs := input.document[i]
	[path, Resources] := walk(docs)
	resource := Resources[name]
	resource.Type == "AWS::Elasticsearch::Domain"
	properties := resource.Properties

	properties.EncryptionAtRestOptions.Enabled != true

	result := {
		"documentId": input.document[i].id,
		"resourceType": resource.Type,
		"resourceName": cf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("%s%s.Properties.EncryptionAtRestOptions.Enabled", [cf_lib.getPath(path),name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("Resources.%s.Properties.EncryptionAtRestOptions should be enabled", [name]),
		"keyActualValue": sprintf("Resources.%s.Properties.EncryptionAtRestOptions is disabled", [name]),
	}
}
