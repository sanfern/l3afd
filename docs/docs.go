// Package docs GENERATED BY SWAG; DO NOT EDIT
// This file was generated by swaggo/swag
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/l3af/configs/v1": {
            "get": {
                "description": "Returns details of the configuration of eBPF Programs for all interfaces on a node",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Retrieve"
                ],
                "summary": "Returns details of the configuration of eBPF Programs for all interfaces on a node",
                "responses": {
                    "200": {
                        "description": ""
                    }
                }
            }
        },
        "/l3af/configs/v1/update": {
            "post": {
                "description": "Update eBPF Programs configuration",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Update"
                ],
                "summary": "Update eBPF Programs configuration",
                "parameters": [
                    {
                        "description": "BPF programs",
                        "name": "cfgs",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/models.L3afBPFPrograms"
                            }
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": ""
                    }
                }
            }
        },
        "/l3af/configs/v1/{iface}": {
            "get": {
                "description": "Returns details of the configuration of eBPF Programs for a given interface",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "Retrieve"
                ],
                "summary": "Returns details of the configuration of eBPF Programs for a given interface",
                "parameters": [
                    {
                        "type": "string",
                        "description": "interface name",
                        "name": "iface",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": ""
                    }
                }
            }
        }
    },
    "definitions": {
        "models.BPFProgram": {
            "type": "object",
            "properties": {
                "admin_status": {
                    "type": "string"
                },
                "artifact": {
                    "type": "string"
                },
                "cfg_version": {
                    "type": "integer"
                },
                "cmd_config": {
                    "type": "string"
                },
                "cmd_start": {
                    "type": "string"
                },
                "cmd_status": {
                    "type": "string"
                },
                "cmd_stop": {
                    "type": "string"
                },
                "config_args": {
                    "$ref": "#/definitions/models.L3afDNFArgs"
                },
                "config_file_path": {
                    "type": "string"
                },
                "cpu": {
                    "type": "integer"
                },
                "id": {
                    "type": "integer"
                },
                "is_plugin": {
                    "type": "boolean"
                },
                "map_args": {
                    "$ref": "#/definitions/models.L3afDNFArgs"
                },
                "map_name": {
                    "type": "string"
                },
                "memory": {
                    "type": "integer"
                },
                "monitor_maps": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.L3afDNFMetricsMap"
                    }
                },
                "name": {
                    "type": "string"
                },
                "prog_type": {
                    "type": "string"
                },
                "rules": {
                    "type": "string"
                },
                "rules_file": {
                    "type": "string"
                },
                "seq_id": {
                    "type": "integer"
                },
                "start_args": {
                    "$ref": "#/definitions/models.L3afDNFArgs"
                },
                "status_args": {
                    "$ref": "#/definitions/models.L3afDNFArgs"
                },
                "stop_args": {
                    "$ref": "#/definitions/models.L3afDNFArgs"
                },
                "user_program_daemon": {
                    "type": "boolean"
                },
                "version": {
                    "type": "string"
                }
            }
        },
        "models.BPFPrograms": {
            "type": "object",
            "properties": {
                "tc_egress": {
                    "description": "list of tc egress bpf programs",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.BPFProgram"
                    }
                },
                "tc_ingress": {
                    "description": "list of tc ingress bpf programs",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.BPFProgram"
                    }
                },
                "xdp_ingress": {
                    "description": "list of xdp bpf programs",
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/models.BPFProgram"
                    }
                }
            }
        },
        "models.L3afBPFPrograms": {
            "type": "object",
            "properties": {
                "bpf_programs": {
                    "description": "list of bpf programs",
                    "$ref": "#/definitions/models.BPFPrograms"
                },
                "host_name": {
                    "description": "host name or pod name",
                    "type": "string"
                },
                "iface": {
                    "description": "Interface name",
                    "type": "string"
                }
            }
        },
        "models.L3afDNFArgs": {
            "type": "object",
            "additionalProperties": true
        },
        "models.L3afDNFMetricsMap": {
            "type": "object",
            "properties": {
                "aggregator": {
                    "type": "string"
                },
                "key": {
                    "type": "integer"
                },
                "name": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/",
	Schemes:          []string{},
	Title:            "L3AFD APIs",
	Description:      "Configuration APIs to deploy and get the details of the eBPF Programs on the node",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
