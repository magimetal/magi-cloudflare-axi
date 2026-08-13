# Cloudflare capability parity (generated)

Pinned source: `70ff690553722f731849ede6ba9ce98958395a23`
Denominator: **172**. Full parity is not claimed.

## Parity dimensions

| Dimension | Status counts | Complete |
|---|---|---|
| inventory | {"complete": 172, "unresolved": 0} | 172 |
| schema | {"complete": 168, "unresolved": 0, "zero_input_evidenced": 4} | 172 |
| route | {"complete": 15, "external_blocked": 0, "unresolved": 157} | 15 |
| behavior | {"specified": 0, "unresolved": 157, "verified": 15} | 15 |
| policy | {"classified": 0, "unresolved": 157, "verified": 15} | 15 |
| verification | {"hermetic_verified": 15, "unverified": 157} | 15 |
| discovery | {"generated": 5, "missing": 157, "verified": 10} | 10 |
| external_blocker | {"none": 132, "open": 40, "resolved": 0} | 132 |

## Global parity

| I | S | R | B | P | V | D | X |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 172 | 172 | 15 | 15 | 15 | 15 | 10 | 40 |

## Family summary

| Group | Count | I | S | R | B | P | V | D | X |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ai-gateway | 5 | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| auditlogs | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| autorag | 3 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| browser-rendering | 13 | 13 | 13 | 7 | 7 | 7 | 7 | 6 | 0 |
| cloudflare-blog | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 0 |
| cloudflare-one-casb | 11 | 11 | 11 | 0 | 0 | 0 | 0 | 0 | 11 |
| demo-day | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| dex-analysis | 18 | 18 | 18 | 0 | 0 | 0 | 0 | 0 | 18 |
| dns-analytics | 3 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| graphql | 6 | 6 | 6 | 1 | 1 | 1 | 1 | 0 | 0 |
| logpush | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| radar | 66 | 66 | 66 | 0 | 0 | 0 | 0 | 0 | 0 |
| sandbox-container | 7 | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 7 |
| shared | 7 | 7 | 7 | 1 | 1 | 1 | 1 | 0 | 0 |
| stack-mcp | 2 | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 1 |
| workers-bindings | 18 | 18 | 18 | 2 | 2 | 2 | 2 | 0 | 0 |
| workers-builds | 3 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| workers-observability | 3 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 3 |

## Transport summary

| Group | Count | I | S | R | B | P | V | D | X |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| custom_container | 7 | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 7 |
| graphql | 6 | 6 | 6 | 1 | 1 | 1 | 1 | 0 | 0 |
| internal_binding | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| mcp | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |
| public_http | 79 | 79 | 79 | 4 | 4 | 4 | 4 | 4 | 0 |
| rest | 78 | 78 | 78 | 9 | 9 | 9 | 9 | 6 | 32 |

## Access classification summary

| Group | Count | I | S | R | B | P | V | D | X |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| blocked | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| mcp_remote | 26 | 26 | 26 | 1 | 1 | 1 | 1 | 0 | 25 |
| modeled | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 0 |
| public_direct | 6 | 6 | 6 | 4 | 4 | 4 | 4 | 4 | 0 |
| raw_graphql | 6 | 6 | 6 | 1 | 1 | 1 | 1 | 0 | 0 |
| raw_rest | 127 | 127 | 127 | 3 | 3 | 3 | 3 | 0 | 14 |

## Read/write operation summary

| Group | Count | I | S | R | B | P | V | D | X |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| read | 150 | 150 | 150 | 14 | 14 | 14 | 14 | 10 | 34 |
| write | 22 | 22 | 22 | 1 | 1 | 1 | 1 | 0 | 6 |

## Blocker ledger

| ID | Count | X | Status | Family |
|---|---:|---:|---|---|
| B-CASB | 11 | 11 | open | cloudflare-one-casb |
| B-CONTAINER | 7 | 7 | open | sandbox-container |
| B-DEX | 18 | 18 | open | dex-analysis |
| B-OBS | 3 | 3 | open | workers-observability |
| B-STACK | 1 | 1 | open | stack-mcp |

## Capability details

| Name | Family | Transport | Access | Operation | I | S | R | B | P | V | D | X | Blocker |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ai_search | autorag | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| asset_by_id | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| asset_categories_by_type | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| asset_categories_by_vendor | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| asset_categories_by_vendor_and_type | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| asset_categories_list | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| assets_by_category_id | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| assets_by_integration_id | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| assets_list | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| assets_search | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| auditlogs_by_account_id | auditlogs | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| cancel_crawl | browser-rendering | public_http | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| container_exec | sandbox-container | custom_container | mcp_remote | write | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| container_file_delete | sandbox-container | custom_container | mcp_remote | write | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| container_file_read | sandbox-container | custom_container | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| container_file_write | sandbox-container | custom_container | mcp_remote | write | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| container_files_list | sandbox-container | custom_container | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| container_initialize | sandbox-container | custom_container | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| container_ping | sandbox-container | custom_container | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-CONTAINER |
| create_url_scan | radar | public_http | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| d1_database_create | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| d1_database_delete | workers-bindings | rest | raw_rest | write | Y | Y | Y | Y | Y | Y | N | N |  |
| d1_database_get | workers-bindings | rest | raw_rest | read | Y | Y | Y | Y | Y | Y | N | N |  |
| d1_database_query | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| d1_databases_list | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| dex_analyze_warp_diag | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_create_remote_pcap | dex-analysis | rest | mcp_remote | write | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_create_remote_warp_diag | dex-analysis | rest | mcp_remote | write | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_explore_remote_warp_diag_output | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_fleet_status_live | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_fleet_status_logs | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_fleet_status_over_time | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_http_test_details | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_list_colos | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_list_remote_capture_eligible_devices | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_list_remote_captures | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_list_remote_warp_diag_contents | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_list_tests | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_list_warp_change_events | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_test_statistics | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_traceroute_test_details | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_traceroute_test_network_path | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dex_traceroute_test_result_network_path | dex-analysis | rest | mcp_remote | read | Y | Y | N | N | N | N | N | Y | B-DEX |
| dns_report | dns-analytics | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_ai_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_annotations | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_as112_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_as_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_as_relationships | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_as_set | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_hijacks | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_ip_space_timeseries | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_leaks | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_moas | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_pfx2as | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_route_stats | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_routes_realtime | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_routing_table_ases | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_rpki_aspa_changes | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_rpki_aspa_snapshot | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_rpki_aspa_timeseries | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_timeseries | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_top_ases | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_top_ases_by_prefixes | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bgp_top_prefixes | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bot_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bots_crawlers_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_bots_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_certificate_transparency_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_crawl_result | browser-rendering | rest | modeled | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| get_ct_authority_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_ct_log_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_dns_queries_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_domain_rank_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_domains_ranking | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_domains_ranking_timeseries | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_email_routing_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_email_security_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_geolocation_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_http_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_internet_quality_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_internet_services_ranking | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_internet_services_timeseries | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_internet_speed_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_ip_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_l3_attack_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_l7_attack_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_leaked_credentials_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_log_details | ai-gateway | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_log_request_body | ai-gateway | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_log_response_body | ai-gateway | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_netflows_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_origin_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_origins_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_outages | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_outages_by_location | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_post | cloudflare-blog | public_http | public_direct | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| get_robots_txt_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_speed_histogram | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_tcp_resets_timeouts_data | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_tld_details | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_traffic_anomalies | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_traffic_anomalies_by_location | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_url_html_content | browser-rendering | rest | raw_rest | read | Y | Y | Y | Y | Y | Y | N | N |  |
| get_url_json | browser-rendering | rest | modeled | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| get_url_links | browser-rendering | rest | modeled | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| get_url_markdown | browser-rendering | rest | modeled | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| get_url_pdf | browser-rendering | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_url_scan | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_url_scan_har | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_url_scan_screenshot | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_url_screenshot | browser-rendering | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| get_url_snapshot | browser-rendering | rest | modeled | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| graphql_api_explorer | graphql | graphql | raw_graphql | read | Y | Y | N | N | N | N | N | N |  |
| graphql_complete_schema | graphql | graphql | raw_graphql | read | Y | Y | N | N | N | N | N | N |  |
| graphql_query | graphql | graphql | raw_graphql | write | Y | Y | N | N | N | N | N | N |  |
| graphql_schema_overview | graphql | graphql | raw_graphql | read | Y | Y | Y | Y | Y | Y | N | N |  |
| graphql_schema_search | graphql | graphql | raw_graphql | read | Y | Y | N | N | N | N | N | N |  |
| graphql_type_details | graphql | graphql | raw_graphql | read | Y | Y | N | N | N | N | N | N |  |
| hyperdrive_config_delete | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| hyperdrive_config_edit | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| hyperdrive_config_get | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| hyperdrive_configs_list | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| integration_by_id | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| integrations_list | cloudflare-one-casb | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-CASB |
| kill_browser_session | browser-rendering | public_http | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| kv_namespace_create | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| kv_namespace_delete | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| kv_namespace_get | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| kv_namespace_update | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| kv_namespaces_list | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_autonomous_systems | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_bots | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_browser_sessions | browser-rendering | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_ct_authorities | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_ct_logs | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_gateways | ai-gateway | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_geolocations | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_libraries | stack-mcp | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_logs | ai-gateway | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_origins | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_posts | cloudflare-blog | public_http | public_direct | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| list_rags | autorag | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| list_tags | cloudflare-blog | public_http | public_direct | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| list_tlds | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| logpush_jobs_by_account_id | logpush | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| mcp_demo_day_info | demo-day | public_http | public_direct | read | Y | Y | N | N | N | N | N | N |  |
| migrate_pages_to_workers_guide | shared | public_http | public_direct | write | Y | Y | N | N | N | N | N | N |  |
| observability_keys | workers-observability | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-OBS |
| observability_values | workers-observability | rest | raw_rest | read | Y | Y | N | N | N | N | N | Y | B-OBS |
| query_worker_observability | workers-observability | rest | raw_rest | write | Y | Y | N | N | N | N | N | Y | B-OBS |
| r2_bucket_create | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| r2_bucket_delete | workers-bindings | rest | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| r2_bucket_get | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| r2_buckets_list | workers-bindings | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| scrape_url_elements | browser-rendering | rest | modeled | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| search | autorag | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| search_cloudflare_documentation | shared | mcp | mcp_remote | read | Y | Y | Y | Y | Y | Y | N | N |  |
| search_dev_stack | stack-mcp | internal_binding | blocked | read | Y | Y | N | N | N | N | N | Y | B-STACK |
| search_posts | cloudflare-blog | public_http | public_direct | read | Y | Y | Y | Y | Y | Y | Y | N |  |
| search_url_scans | radar | public_http | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| show_account_dns_settings | dns-analytics | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| show_zone_dns_settings | dns-analytics | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| start_crawl | browser-rendering | public_http | raw_rest | write | Y | Y | N | N | N | N | N | N |  |
| workers_builds_get_build | workers-builds | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| workers_builds_get_build_logs | workers-builds | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| workers_builds_list_builds | workers-builds | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| workers_get_worker | shared | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| workers_get_worker_code | shared | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| workers_list | shared | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| zone_details | shared | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
| zones_list | shared | rest | raw_rest | read | Y | Y | N | N | N | N | N | N |  |
