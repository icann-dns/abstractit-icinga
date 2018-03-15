# Class icinga
#
# setup icinga
# full docs in README.md

class icinga (
  Stdlib::Ip_address                  $web_ip,
  Stdlib::Port                        $web_port,
  String                              $icinga_user,
  String                              $icinga_group,
  Stdlib::Absolutepath                $cgi_url,
  Stdlib::Absolutepath                $cgi_path,
  Stdlib::Absolutepath                $html_path,
  Optional[Stdlib::Absolutepath]      $css_path,
  Boolean                             $ssl,
  Optional[Stdlib::Absolutepath]      $ssl_cacrt,
  String                              $ssl_cypher_list,
  Boolean                             $manage_ssl,
  Boolean                             $manage_dbs,
  Boolean                             $manage_users,
  Boolean                             $manage_repo,
  Stdlib::Host                        $webhostname,
  Boolean                             $configure_firewall,
  Enum['classic', 'web', 'both']      $gui_type,
  Boolean                             $notifications,
  Boolean                             $embedded_perl,
  Boolean                             $perfdata,
  String                              $perfdatatype,
  Stdlib::Absolutepath                $pnp4nagios_html_path,
  Optional[String]                    $admin_group,
  Optional[String]                    $admin_users,
  Optional[String]                    $ro_users,
  Optional[String]                    $ro_group,
  Integer[0]                          $check_timeout,
  Integer[-1,2048]                    $debug,
  Integer[0,2]                        $debug_verbosity,
  Stdlib::Absolutepath                $debug_file,
  Integer                             $max_debug_file_size,
  Pattern[/^[\w\@\.\-]+$/]            $admin_email,
  Pattern[/^[\w\@\.\-]+$/]            $admin_pager,
  Boolean                             $stalking,
  Boolean                             $flap_detection,
  Boolean                             $enable_ido,
  Enum['mysql', 'pgsql']              $ido_db_server,
  Stdlib::Host                        $ido_db_host,
  Stdlib::Port                        $ido_db_port,
  String                              $ido_db_name,
  String                              $ido_db_user,
  String                              $ido_db_pass,
  Enum['mysql', 'pgsql']              $web_db_server,
  Stdlib::Host                        $web_db_host,
  Stdlib::Port                        $web_db_port,
  String                              $web_db_name,
  String                              $web_db_user,
  String                              $web_db_pass,
  Stdlib::Absolutepath                $web_auth_user_file,
  Stdlib::Absolutepath                $web_auth_group_file,
  Optional[Hash]                      $web_auth_users,
  String                              $web_auth_name,
  Enum['tls', 'ssl', 'none']          $ldap_security,
  Stdlib::Host                        $ldap_server,
  String                              $ldap_firstname,
  String                              $ldap_lastname,
  Pattern[/^[\w\@\.\-]+$/]            $ldap_email,
  Optional[String]                    $ldap_basedn,
  Optional[String]                    $ldap_groupdn,
  Optional[String]                    $ldap_binddn,
  Optional[String]                    $ldap_bindpw,
  String                              $ldap_userattr,
  String                              $ldap_groupattr,
  Optional[String]                    $ldap_filter_extra,
  Optional[String]                    $ldap_auth_group,
  Stdlib::Absolutepath                $nagios_plugins,
  Optional[Stdlib::Absolutepath]      $nagios_extra_plugins,
  String                              $icinga_cmd_grp,
  Optional[String]                    $db_password,
  Optional[String]                    $email_user,
  Optional[String]                    $email_password,
  Optional[Stdlib::Filesource]        $ssl_cert_source,
  Optional[String]                    $clickatell_api_id,
  Optional[String]                    $clickatell_username,
  Optional[String]                    $clickatell_password,
  Boolean                             $is_pbx,
  Optional[String]                    $pbx_mngr_pw,
  Boolean                             $enable_environment_macros,
  Stdlib::Absolutepath                $logfile,
  Array[Stdlib::Absolutepath]         $extra_cfg_files,
  Array[Stdlib::Absolutepath]         $extra_cfg_dirs,
  Stdlib::Absolutepath                $object_cache_file,
  Stdlib::Absolutepath                $precached_object_file,
  Stdlib::Absolutepath                $resource_file,
  Stdlib::Absolutepath                $status_file,
  Integer[1]                          $status_update_interval,
  Boolean                             $check_external_commands,
  Stdlib::Absolutepath                $command_file,
  Integer[1]                          $external_command_buffer_slots,
  Stdlib::Absolutepath                $lock_file,
  Stdlib::Absolutepath                $temp_file,
  Stdlib::Absolutepath                $temp_path,
  Integer[-1]                         $event_broker_options,
  Enum['n', 'h', 'd', 'w', 'm']       $log_rotation_method,
  Stdlib::Absolutepath                $log_archive_path,
  Boolean                             $use_daemon_log,
  Boolean                             $use_syslog,
  Boolean                             $use_syslog_local_facility,
  Integer[0,7]                        $syslog_local_facility,
  Boolean                             $log_notifications,
  Boolean                             $log_service_retries,
  Boolean                             $log_host_retries,
  Boolean                             $log_event_handlers,
  Boolean                             $log_initial_states,
  Boolean                             $log_current_states,
  Boolean                             $log_external_commands,
  Boolean                             $log_passive_checks,
  Boolean                             $log_long_plugin_output,
  Variant[Enum['n', 'd', 's'], Float] $service_inter_check_delay_method,
  Integer[1]                          $max_service_check_spread,
  Variant[Enum['s'], Integer]         $service_interleave_factor,
  Variant[Enum['n', 'd', 's'], Float] $host_inter_check_delay_method,
  Integer[1]                          $max_host_check_spread,
  Integer[0]                          $max_concurrent_checks,
  Integer[1]                          $check_result_reaper_frequency,
  Integer[1]                          $max_check_result_reaper_time,
  Stdlib::Absolutepath                $check_result_path,
  Integer[1]                          $max_check_result_file_age,
  Optional[Integer[0]]                $max_check_result_list_items,
  Integer[1]                          $cached_host_check_horizon,
  Integer[1]                          $cached_service_check_horizon,
  Boolean                             $enable_predictive_host_dependency_checks,
  Boolean                             $enable_predictive_service_dependency_checks,
  Boolean                             $soft_state_dependencies,
  Boolean                             $auto_reschedule_checks,
  Integer[1]                          $auto_rescheduling_interval,
  Integer[1]                          $auto_rescheduling_window,
  Float                               $sleep_time,
  Integer[1]                          $host_check_timeout,
  Integer[1]                          $event_handler_timeout,
  Integer[1]                          $notification_timeout,
  Integer[1]                          $ocsp_timeout,
  Integer[1]                          $perfdata_timeout,
  Boolean                             $retain_state_information,
  Stdlib::Absolutepath                $state_retention_file,
  Optional[Stdlib::Absolutepath]      $sync_retention_file,
  Integer[1]                          $retention_update_interval,
  Boolean                             $use_retained_program_state,
  Boolean                             $dump_retained_host_service_states_to_neb,
  Boolean                             $use_retained_scheduling_info,
  Integer[0]                          $retained_host_attribute_mask,
  Integer[0]                          $retained_service_attribute_mask,
  Integer[0]                          $retained_process_host_attribute_mask,
  Integer[0]                          $retained_process_service_attribute_mask,
  Integer[0]                          $retained_contact_host_attribute_mask,
  Integer[0]                          $retained_contact_service_attribute_mask,
  Integer[1]                          $interval_length,
  Boolean                             $use_aggressive_host_checking,
  Boolean                             $execute_service_checks,
  Boolean                             $accept_passive_service_checks,
  Boolean                             $execute_host_checks,
  Boolean                             $accept_passive_host_checks,
  Boolean                             $enable_event_handlers,
  Boolean                             $enable_state_based_escalation_ranges,
  Optional[String]                    $host_perfdata_command,
  Optional[String]                    $service_perfdata_command,
  Optional[Stdlib::Absolutepath]      $host_perfdata_file,
  Optional[Stdlib::Absolutepath]      $service_perfdata_file,
  Optional[String]                    $host_perfdata_file_template,
  Optional[String]                    $service_perfdata_file_template,
  Optional[Enum['w', 'p', 'a']]       $host_perfdata_file_mode,
  Optional[Enum['w', 'p', 'a']]       $service_perfdata_file_mode,
  Optional[String]                    $host_perfdata_file_processing_interval,
  Optional[String]                    $service_perfdata_file_processing_interval,
  Optional[String]                    $host_perfdata_file_processing_command,
  Optional[String]                    $service_perfdata_file_processing_command,
  Boolean                             $host_perfdata_process_empty_results,
  Boolean                             $service_perfdata_process_empty_results,
  Boolean                             $allow_empty_hostgroup_assignment,
  Boolean                             $obsess_over_services,
  Optional[String]                    $ocsp_command,
  Boolean                             $obsess_over_hosts,
  Optional[String]                    $ochp_command,
  Boolean                             $translate_passive_host_checks,
  Boolean                             $passive_host_checks_are_soft,
  Boolean                             $check_for_orphaned_services,
  Boolean                             $check_for_orphaned_hosts,
  Enum['c', 'w', 'u', 'o']            $service_check_timeout_state,
  Boolean                             $check_service_freshness,
  Integer[1]                          $service_freshness_check_interval,
  Boolean                             $check_host_freshness,
  Integer[1]                          $host_freshness_check_interval,
  Integer[1]                          $additional_freshness_latency,
  Float                               $low_service_flap_threshold,
  Float                               $high_service_flap_threshold,
  Float                               $low_host_flap_threshold,
  Float                               $high_host_flap_threshold,
  String                              $date_format,
  Stdlib::Absolutepath                $p1_file,
  Boolean                             $use_embedded_perl_implicitly,
  Boolean                             $keep_unknown_macros,
  Boolean                             $use_regexp_matching,
  Boolean                             $use_true_regexp_matching,
  Boolean                             $daemon_dumps_core,
  Boolean                             $use_large_installation_tweaks,
  Boolean                             $child_processes_fork_twice,
  Boolean                             $event_profiling_enabled,
  Variant[Integer[-1], Pattern[/\ds?/]]         $command_check_interval,
  Enum['internal', 'httpbasic', 'ldap', 'none'] $web_auth_type,
) {

  if $manage_users {
    include ::icinga::users
    Class['icinga::users'] -> Class['icinga::install']
  }

  include ::icinga::install
  include ::icinga::idoconfig
  include ::icinga::idoservice
  include ::icinga::config
  include ::icinga::nagios_resources
  include ::icinga::service


  Class['icinga::install'] -> Class['icinga::idoconfig']
  Class['icinga::install'] -> Class['icinga::gui']
  Class['icinga::idoconfig'] ~> Class['icinga::idoservice']

  Class['icinga::config'] ~> Class['icinga::service']
  Class['icinga::nagios_resources'] ~> Class['icinga::service']

  include ::icinga::gui

  if ( $perfdata  and $perfdatatype =~ /^pnp4nagios$/ ) {
    include ::pnp4nagios
  }
}
