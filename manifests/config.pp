# Class icinga::config
#
# Configures icinga using the defaults set in the params class
# should not be called directly
class icinga::config {
  $icinga_user          = $::icinga::icinga_user
  $icinga_group         = $::icinga::icinga_group
  $icinga_cmd_grp       = $::icinga::icinga_cmd_grp
  $notifications        = $::icinga::notifications
  $enable_ido           = $::icinga::enable_ido
  $embedded_perl        = $::icinga::embedded_perl
  $perfdata             = $::icinga::perfdata
  $perfdatatype         = $::icinga::perfdatatype
  $admin_group          = $::icinga::admin_group
  $nagios_plugins       = $::icinga::nagios_plugins
  $nagios_extra_plugins = $::icinga::nagios_extra_plugins
  $db_password          = $::icinga::db_password
  $email_password       = $::icinga::email_password
  $check_timeout        = $::icinga::check_timeout
  $clickatell_api_id    = $::icinga::clickatell_api_id
  $clickatell_username  = $::icinga::clickatell_username
  $clickatell_password  = $::icinga::clickatell_password
  $is_pbx               = $::icinga::is_pbx
  $pbx_mngr_pw          = $::icinga::pbx_mngr_pw
  $debug                = $::icinga::debug
  $debug_verbosity      = $icinga::debug_verbosity
  $debug_file           = $icinga::debug_file
  $max_debug_file_size  = $icinga::max_debug_file_size
  $admin_email          = $::icinga::admin_email
  $admin_pager          = $::icinga::admin_pager
  $stalking             = $::icinga::stalking
  $flap_detection       = $::icinga::flap_detection
  $gui_type             = $::icinga::gui_type
  $enable_environment_macros = $::icinga::enable_environment_macros
  $logfile                                  = $icinga::logfile
  $extra_cfg_files                          = $icinga::extra_cfg_files
  $extra_cfg_dirs                           = $icinga::extra_cfg_dirs
  $object_cache_file                        = $icinga::object_cache_file
  $precached_object_file                    = $icinga::precached_object_file
  $resource_file                            = $icinga::resource_file
  $status_file                              = $icinga::status_file
  $status_update_interval                   = $icinga::status_update_interval
  $check_external_commands                  = $icinga::check_external_commands
  $command_check_interval                   = $icinga::command_check_interval
  $command_file                             = $icinga::command_file
  $external_command_buffer_slots            = $icinga::external_command_buffer_slots
  $lock_file                                = $icinga::lock_file
  $temp_file                                = $icinga::temp_file
  $temp_path                                = $icinga::temp_path
  $event_broker_options                     = $icinga::event_broker_options
  $log_rotation_method                      = $icinga::log_rotation_method
  $log_archive_path                         = $icinga::log_archive_path
  $use_daemon_log                           = $icinga::use_daemon_log
  $use_syslog                               = $icinga::use_syslog
  $use_syslog_local_facility                = $icinga::use_syslog_local_facility
  $syslog_local_facility                    = $icinga::syslog_local_facility
  $log_notifications                        = $icinga::log_notifications
  $log_service_retries                      = $icinga::log_service_retries
  $log_host_retries                         = $icinga::log_host_retries
  $log_event_handlers                       = $icinga::log_event_handlers
  $log_initial_states                       = $icinga::log_initial_states
  $log_current_states                       = $icinga::log_current_states
  $log_external_commands                    = $icinga::log_external_commands
  $log_passive_checks                       = $icinga::log_passive_checks
  $log_long_plugin_output                   = $icinga::log_long_plugin_output
  $service_inter_check_delay_method       = $icinga::service_inter_check_delay_method
  $max_service_check_spread                 = $icinga::max_service_check_spread
  $service_interleave_factor                = $icinga::service_interleave_factor
  $host_inter_check_delay_method            = $icinga::host_inter_check_delay_method
  $max_host_check_spread                    = $icinga::max_host_check_spread
  $max_concurrent_checks                    = $icinga::max_concurrent_checks
  $check_result_reaper_frequency            = $icinga::check_result_reaper_frequency
  $max_check_result_reaper_time             = $icinga::max_check_result_reaper_time
  $check_result_path                        = $icinga::check_result_path
  $max_check_result_file_age                = $icinga::max_check_result_file_age
  $max_check_result_list_items              = $icinga::max_check_result_list_items
  $cached_host_check_horizon                = $icinga::cached_host_check_horizon
  $cached_service_check_horizon             = $icinga::cached_service_check_horizon
  $enable_predictive_host_dependency_checks = $icinga::enable_predictive_host_dependency_checks
  $enable_predictive_service_dependency_checks = $icinga::enable_predictive_service_dependency_checks
  $soft_state_dependencies                   = $icinga::soft_state_dependencies
  $auto_reschedule_checks                    = $icinga::auto_reschedule_checks
  $auto_rescheduling_interval                = $icinga::auto_rescheduling_interval
  $auto_rescheduling_window                  = $icinga::auto_rescheduling_window
  $sleep_time                                = $icinga::sleep_time
  $host_check_timeout                        = $icinga::host_check_timeout
  $event_handler_timeout                     = $icinga::event_handler_timeout
  $notification_timeout                      = $icinga::notification_timeout
  $ocsp_timeout                              = $icinga::ocsp_timeout
  $perfdata_timeout                          = $icinga::perfdata_timeout
  $retain_state_information                  = $icinga::retain_state_information
  $state_retention_file                      = $icinga::state_retention_file
  $sync_retention_file                       = $icinga::sync_retention_file
  $retention_update_interval                 = $icinga::retention_update_interval
  $use_retained_program_state                = $icinga::use_retained_program_state
  $dump_retained_host_service_states_to_neb  = $icinga::dump_retained_host_service_states_to_neb
  $use_retained_scheduling_info              = $icinga::use_retained_scheduling_info
  $retained_host_attribute_mask              = $icinga::retained_host_attribute_mask
  $retained_service_attribute_mask           = $icinga::retained_service_attribute_mask
  $retained_process_host_attribute_mask = $icinga::retained_process_host_attribute_mask
  $retained_process_service_attribute_mask = $icinga::retained_process_service_attribute_mask
  $retained_contact_host_attribute_mask = $icinga::retained_contact_host_attribute_mask
  $retained_contact_service_attribute_mask = $icinga::retained_contact_service_attribute_mask
  $interval_length                           = $icinga::interval_length
  $use_aggressive_host_checking              = $icinga::use_aggressive_host_checking
  $execute_service_checks                    = $icinga::execute_service_checks
  $accept_passive_service_checks             = $icinga::accept_passive_service_checks
  $execute_host_checks                       = $icinga::execute_host_checks
  $accept_passive_host_checks                = $icinga::accept_passive_host_checks
  $enable_event_handlers                     = $icinga::enable_event_handlers
  $enable_state_based_escalation_ranges = $icinga::enable_state_based_escalation_ranges
  $host_perfdata_command                     = $icinga::host_perfdata_command
  $service_perfdata_command                  = $icinga::service_perfdata_command
  $host_perfdata_file                        = $icinga::host_perfdata_file
  $service_perfdata_file                     = $icinga::service_perfdata_file
  $host_perfdata_file_template               = $icinga::host_perfdata_file_template
  $service_perfdata_file_template            = $icinga::service_perfdata_file_template
  $host_perfdata_file_mode                   = $icinga::host_perfdata_file_mode
  $service_perfdata_file_mode                = $icinga::service_perfdata_file_mode
  $host_perfdata_file_processing_interval = $icinga::host_perfdata_file_processing_interval
  $service_perfdata_file_processing_interval = $icinga::service_perfdata_file_processing_interval
  $host_perfdata_file_processing_command    = $icinga::host_perfdata_file_processing_command
  $service_perfdata_file_processing_command = $icinga::service_perfdata_file_processing_command
  $host_perfdata_process_empty_results      = $icinga::host_perfdata_process_empty_results
  $service_perfdata_process_empty_results   = $icinga::service_perfdata_process_empty_results
  $allow_empty_hostgroup_assignment         = $icinga::allow_empty_hostgroup_assignment
  $obsess_over_services                     = $icinga::obsess_over_services
  $ocsp_command                             = $icinga::ocsp_command
  $obsess_over_hosts                        = $icinga::obsess_over_hosts
  $ochp_command                             = $icinga::ochp_command
  $translate_passive_host_checks            = $icinga::translate_passive_host_checks
  $passive_host_checks_are_soft             = $icinga::passive_host_checks_are_soft
  $check_for_orphaned_services              = $icinga::check_for_orphaned_services
  $check_for_orphaned_hosts                 = $icinga::check_for_orphaned_hosts
  $service_check_timeout_state              = $icinga::service_check_timeout_state
  $check_service_freshness                  = $icinga::check_service_freshness
  $service_freshness_check_interval         = $icinga::service_freshness_check_interval
  $check_host_freshness                     = $icinga::check_host_freshness
  $host_freshness_check_interval            = $icinga::host_freshness_check_interval
  $additional_freshness_latency             = $icinga::additional_freshness_latency
  $low_service_flap_threshold               = $icinga::low_service_flap_threshold
  $high_service_flap_threshold              = $icinga::high_service_flap_threshold
  $low_host_flap_threshold                  = $icinga::low_host_flap_threshold
  $high_host_flap_threshold                 = $icinga::high_host_flap_threshold
  $date_format                              = $icinga::date_format
  $p1_file                                  = $icinga::p1_file
  $use_embedded_perl_implicitly             = $icinga::use_embedded_perl_implicitly
  $keep_unknown_macros                      = $icinga::keep_unknown_macros
  $use_regexp_matching                      = $icinga::use_regexp_matching
  $use_true_regexp_matching                 = $icinga::use_true_regexp_matching
  $daemon_dumps_core                        = $icinga::daemon_dumps_core
  $use_large_installation_tweaks            = $icinga::use_large_installation_tweaks
  $child_processes_fork_twice               = $icinga::child_processes_fork_twice
  $event_profiling_enabled                  = $icinga::event_profiling_enabled

  $ensure_idoutils = $enable_ido? {
    default => 'file',
    false => 'absent',
  }

  $ensure_perf_mod = $perfdata? {
    default => 'file',
    false => 'absent',
  }
  if $gui_type != 'classic' {
    file{ '/etc/icinga-web':
      ensure  => directory,
      group   => $icinga_cmd_grp,
      recurse => true,
    }
  }

  file { '/etc/default/icinga':
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('icinga/etc/default/icinga.erb'),
    notify  => [Class[icinga::service],Class[icinga::idoservice]],
    require => Class[icinga::install],
  }

  file { '/etc/icinga/icinga.cfg':
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0644',
    notify  => Class[icinga::service],
    content => template('icinga/etc/icinga/icinga.cfg.erb'),
    require => Class[icinga::install],
  }

  file { '/etc/icinga/modules/perf_module.cfg':
    ensure  => $ensure_perf_mod,
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0644',
    notify  => Class[icinga::service],
    source  => 'puppet:///modules/icinga/etc/icinga/modules/perf_module.cfg',
    require => Class[icinga::install],
  }

  file { '/etc/icinga/modules/idoutils.cfg':
    ensure  => $ensure_idoutils,
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0644',
    notify  => Class[icinga::service],
    source  => 'puppet:///modules/icinga/etc/icinga/modules/idoutils.cfg',
    require => Class[icinga::install],
  }

  file { '/etc/icinga/idoutils.cfg':
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0644',
    notify  => Class[icinga::service],
    source  => 'puppet:///modules/icinga/etc/icinga/idoutils.cfg',
    require => Class[icinga::install],
  }
  file { '/etc/icinga/resource.cfg':
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0644',
    notify  => Class[icinga::service],
    content => template('icinga/etc/icinga/resource.cfg.erb'),
    require => Class[icinga::install],
  }

  file { '/etc/icinga/conf.d':
    ensure  => directory,
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0775',
    require => Class[icinga::install],
  }

  file { '/var/log/icinga':
    ensure => directory,
    owner  => $icinga_user,
    group  => $icinga_group,
    mode   => '0775',
  }

  file { '/var/log/icinga/archives':
    ensure  => directory,
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0775',
    require => File['/var/log/icinga']
  }

  file { '/var/spool/icinga':
    ensure => directory,
    owner  => $icinga_user,
    group  => $icinga_group,
    mode   => '0755',
  }

  file { '/var/spool/icinga/checkresults':
    ensure  => directory,
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0775',
    require => File['/var/spool/icinga']
  }

  file { '/var/spool/icinga/cmd':
    ensure  => directory,
    owner   => $icinga_user,
    group   => $icinga_cmd_grp,
    mode    => '2755',
    require => File['/var/spool/icinga'],
  }
  # This needs to be managed much better but we will hack it for now
  file { '/var/lib/icinga/rw/icinga.cmd':
    ensure => link,
    target => '/var/spool/icinga/cmd/icinga.cmd',
  }

  file { '/var/run/icinga':
    ensure => directory,
    owner  => $icinga_user,
    group  => $icinga_group,
    mode   => '0775',
  }

  file { '/var/run/icinga/icinga.pid':
    ensure  => file,
    owner   => $icinga_user,
    group   => $icinga_group,
    mode    => '0644',
    require => File['/var/run/icinga']
  }
}

