import os

from api.base import ApiBase
from api.parameters import *
from api import winbase_objects as wbo
import utilities as util

class WinBase(ApiBase):
    def __init__(self):
        super().__init__()
        self.__atoms_table = wbo.AtomsTable()
        self._add_functions({
            'AccessCheckAndAuditAlarmA': [self.__access_check_and_audit_alarm_A, self.__access_check_and_audit_alarm_A_arguments],
            'AccessCheckByTypeAndAuditAlarmA': [self.__access_check_by_type_and_audit_alarm_A, self.__access_check_by_type_and_audit_alarm_A_arguments],
            'AccessCheckByTypeResultListAndAuditAlarmA': [self.__access_check_by_type_result_list_and_audit_alarm_A, self.__access_check_by_type_result_list_and_audit_alarm_A_arguments],
            'AccessCheckByTypeResultListAndAuditAlarmByHandleA': [self.__access_check_by_type_result_list_and_audit_alarm_by_handle_A, self.__access_check_by_type_result_list_and_audit_alarm_by_handle_A_arguments],
            'ActivateActCtx': [self.__activate_act_ctx, self.__activate_act_ctx_arguments],
            'AddAtomA': [self.__add_atom_A, self.__add_atom_A_arguments],
            'AddAtomW': [self.__add_atom_A, self.__add_atom_A_arguments],
            'AddConditionalAce': [self.__add_conditional_ace, self.__add_conditional_ace_arguments],
            'AddIntegrityLabelToBoundaryDescriptor': [self.__add_integrity_label_to_boundary_descriptor, self.__add_integrity_label_to_boundary_descriptor_arguments],
            'AddRefActCtx': [self.__add_ref_act_ctx, self.__add_ref_act_ctx_arguments],
            'AddSecureMemoryCacheCallback': [self.__add_secure_memory_cache_callback, self.__add_secure_memory_cache_callback_arguments],
            'ApplicationRecoveryFinished': [self.__application_recovery_finished, self.__application_recovery_finished_arguments],
            'ApplicationRecoveryInProgress': [self.__application_recovery_in_progress, self.__application_recovery_in_progress_arguments],
            'BackupEventLogA': [self.__backup_event_log_A, self.__backup_event_log_A_arguments],
            'BackupEventLogW': [self.__backup_event_log_A, self.__backup_event_log_A_arguments],
            'BackupRead': [self.__backup_read, self.__backup_read_arguments],
            'BackupSeek': [self.__backup_seek, self.__backup_seek_arguments],
            'BackupWrite': [self.__backup_write, self.__backup_write_arguments],
            'BeginUpdateResourceA': [self.__begin_update_resource_A, self.__begin_update_resource_A_arguments],
            'BeginUpdateResourceW': [self.__begin_update_resource_A, self.__begin_update_resource_A_arguments],
            'BindIoCompletionCallback': [self.__bind_io_completion_callback, self.__bind_io_completion_callback_arguments],
            'BuildCommDCBA': [self.__build_comm_DCBA, self.__build_comm_DCBA_arguments],
            'BuildCommDCBAndTimeoutsA': [self.__build_comm_DCB_and_timeouts_A, self.__build_comm_DCB_and_timeouts_A_arguments],
            'BuildCommDCBAndTimeoutsW': [self.__build_comm_DCB_and_timeouts_A, self.__build_comm_DCB_and_timeouts_A_arguments],
            'BuildCommDCBW': [self.__build_comm_DCBA, self.__build_comm_DCBA_arguments],
            'CallNamedPipeA': [self.__call_named_pipe_A, self.__call_named_pipe_A_arguments],
            'CheckNameLegalDOS8Dot3A': [self.__check_name_legal_DOS8Dot3_A, self.__check_name_legal_DOS8Dot3_A_arguments],
            'CheckNameLegalDOS8Dot3W': [self.__check_name_legal_DOS8Dot3_A, self.__check_name_legal_DOS8Dot3_A_arguments],
            'ClearCommBreak': [self.__clear_comm_break, self.__clear_comm_break_arguments],
            'ClearCommError': [self.__clear_comm_error, self.__clear_comm_error_arguments],
            'ClearEventLogA': [self.__clear_event_log_A, self.__clear_event_log_A_arguments],
            'ClearEventLogW': [self.__clear_event_log_A, self.__clear_event_log_A_arguments],
            'CloseEncryptedFileRaw': [self.__close_encrypted_file_raw, self.__close_encrypted_file_raw_arguments],
            'CloseEventLog': [self.__close_event_log, self.__close_event_log_arguments],
            'CommConfigDialogA': [self.__comm_config_dialog_A, self.__comm_config_dialog_A_arguments],
            'CommConfigDialogW': [self.__comm_config_dialog_A, self.__comm_config_dialog_A_arguments],
            'ConvertFiberToThread': [self.__convert_fiber_to_thread, self.__convert_fiber_to_thread_arguments],
            'ConvertThreadToFiber': [self.__convert_thread_to_fiber, self.__convert_thread_to_fiber_arguments],
            'ConvertThreadToFiberEx': [self.__convert_thread_to_fiber_ex, self.__convert_thread_to_fiber_ex_arguments],
            'CopyContext': [self.__copy_context, self.__copy_context_arguments],
            'CopyFile': [self.__copy_file, self.__copy_file_arguments],
            'CopyFile2': [self.__copy_file_2, self.__copy_file_2_arguments],
            'CopyFileA': [self.__copy_file, self.__copy_file_arguments],
            'CopyFileExA': [self.__copy_file_ex_A, self.__copy_file_ex_A_arguments],
            'CopyFileExW': [self.__copy_file_ex_A, self.__copy_file_ex_A_arguments],
            'CopyFileTransactedA': [self.__copy_file_transacted_A, self.__copy_file_transacted_A_arguments],
            'CopyFileTransactedW': [self.__copy_file_transacted_A, self.__copy_file_transacted_A_arguments],
            'CopyFileW': [self.__copy_file, self.__copy_file_arguments],
            'CreateActCtxA': [self.__create__act_ctx_A, self.__create__act_ctx_A_arguments],
            'CreateActCtxW': [self.__create__act_ctx_A, self.__create__act_ctx_A_arguments],
            'CreateBoundaryDescriptorA': [self.__create_boundary_descriptor_A, self.__create_boundary_descriptor_A_arguments],
            'CreateDirectory': [self.__create_directory, self.__create_directory_arguments],
            'CreateDirectoryExA': [self.__create_directory_ex_A, self.__create_directory_ex_A_arguments],
            'CreateDirectoryExW': [self.__create_directory_ex_A, self.__create_directory_ex_A_arguments],
            'CreateDirectoryTransactedA': [self.__create_directory_transacted_A, self.__create_directory_transacted_A_arguments],
            'CreateDirectoryTransactedW': [self.__create_directory_transacted_A, self.__create_directory_transacted_A_arguments],
            'CreateFiber': [self.__create_fiber, self.__create_fiber_arguments],
            'CreateFiberEx': [self.__create_fiber_ex, self.__create_fiber_ex_arguments],
            'CreateFileMappingA': [self.__create_file_mapping_A, self.__create_file_mapping_A_arguments],
            'CreateFileMappingNumaA': [self.__create_file_mapping_numa_A, self.__create_file_mapping_numa_A_arguments],
            'CreateFileTransactedA': [self.__create_file_transacted_A, self.__create_file_transacted_A_arguments],
            'CreateFileTransactedW': [self.__create_file_transacted_A, self.__create_file_transacted_A_arguments],
            'CreateHardLinkA': [self.__create_hard_link_A, self.__create_hard_link_A_arguments],
            'CreateHardLinkTransactedA': [self.__create_hard_link_transacted_A, self.__create_hard_link_transacted_A_arguments],
            'CreateHardLinkTransactedW': [self.__create_hard_link_transacted_A, self.__create_hard_link_transacted_A_arguments],
            'CreateHardLinkW': [self.__create_hard_link_A, self.__create_hard_link_A_arguments],
            'CreateJobObjectA': [self.__create_job_object_A, self.__create_job_object_A_arguments],
            'CreateMailslotA': [self.__create_mailslot_A, self.__create_mailslot_A_arguments],
            'CreateMailslotW': [self.__create_mailslot_A, self.__create_mailslot_A_arguments],
            'CreateNamedPipeA': [self.__create_named_pipe_A, self.__create_named_pipe_A_arguments],
            'CreatePrivateNamespaceA': [self.__create_private_namespace_A, self.__create_private_namespace_A_arguments],
            'CreateProcessWithLogonW': [self.__create_process_with_logon_W, self.__create_process_with_logon_W_arguments],
            'CreateProcessWithTokenW': [self.__create_process_with_token_W, self.__create_process_with_token_W_arguments],
            'CreateSemaphoreA': [self.__create_semaphore_A, self.__create_semaphore_A_arguments],
            'CreateSemaphoreExA': [self.__create_semaphore_ex_A, self.__create_semaphore_ex_A_arguments],
            'CreateSymbolicLinkA': [self.__create_symbolic_link_A, self.__create_symbolic_link_A_arguments],
            'CreateSymbolicLinkTransactedA': [self.__create_symbolic_link_transacted_A, self.__create_symbolic_link_transacted_A_arguments],
            'CreateSymbolicLinkTransactedW': [self.__create_symbolic_link_transacted_A, self.__create_symbolic_link_transacted_A_arguments],
            'CreateSymbolicLinkW': [self.__create_symbolic_link_A, self.__create_symbolic_link_A_arguments],
            'CreateTapePartition': [self.__create_tape_partition, self.__create_tape_partition_arguments],
            'CreateUmsCompletionList': [self.__create_ums_completion_list, self.__create_ums_completion_list_arguments],
            'CreateUmsThreadContext': [self.__create_ums_thread_context, self.__create_ums_thread_context_arguments],
            'DeactivateActCtx': [self.__deactivate_act_ctx, self.__deactivate_act_ctx_arguments],
            'DebugBreakProcess': [self.__debug_break_process, self.__debug_break_process_arguments],
            'DebugSetProcessKillOnExit': [self.__debug_set_process_kill_on_exit, self.__debug_set_process_kill_on_exit_arguments],
            'DecryptFileA': [self.__decrypt_file_A, self.__decrypt_file_A_arguments],
            'DecryptFileW': [self.__decrypt_file_A, self.__decrypt_file_A_arguments],
            'DefineDosDeviceA': [self.__define_dos_device_A, self.__define_dos_device_A_arguments],
            'DeleteAtom': [self.__delete_atom, self.__delete_atom_arguments],
            'DeleteFiber': [self.__delete_fiber, self.__delete_fiber_arguments],
            'DeleteFile': [self.__delete_file, self.__delete_file_arguments],
            'DeleteFileTransactedA': [self.__delete_file_transacted_A, self.__delete_file_transacted_A_arguments],
            'DeleteFileTransactedW': [self.__delete_file_transacted_A, self.__delete_file_transacted_A_arguments],
            'DeleteTimerQueue': [self.__delete_timer_queue, self.__delete_timer_queue_arguments],
            'DeleteUmsCompletionList': [self.__delete_ums_completion_list, self.__delete_ums_completion_list_arguments],
            'DeleteUmsThreadContext': [self.__delete_ums_thread_context, self.__delete_ums_thread_context_arguments],
            'DeleteVolumeMountPointA': [self.__delete_volume_mount_point_A, self.__delete_volume_mount_point_A_arguments],
            'DequeueUmsCompletionListItems': [self.__dequeue_ums_completion_list_items, self.__dequeue_ums_completion_list_items_arguments],
            'DeregisterEventSource': [self.__deregister_event_source, self.__deregister_event_source_arguments],
            'DestroyThreadpoolEnvironment': [self.__destroy_threadpool_environment, self.__destroy_threadpool_environment_arguments],
            'DisableThreadProfiling': [self.__disable_thread_profiling, self.__disable_thread_profiling_arguments],
            'DnsHostnameToComputerNameA': [self.__dns_hostname_to_computer_name_A, self.__dns_hostname_to_computer_name_A_arguments],
            'DnsHostnameToComputerNameW': [self.__dns_hostname_to_computer_name_A, self.__dns_hostname_to_computer_name_A_arguments],
            'DosDateTimeToFileTime': [self.__dos_date_time_to_file_time, self.__dos_date_time_to_file_time_arguments],
            'EnableThreadProfiling': [self.__enable_thread_profiling, self.__enable_thread_profiling_arguments],
            'EncryptFileA': [self.__encrypt_file_A, self.__encrypt_file_A_arguments],
            'EncryptFileW': [self.__encrypt_file_A, self.__encrypt_file_A_arguments],
            'EndUpdateResourceA': [self.__end_update_resource_A, self.__end_update_resource_A_arguments],
            'EndUpdateResourceW': [self.__end_update_resource_A, self.__end_update_resource_A_arguments],
            'EnterUmsSchedulingMode': [self.__enter_ums_scheduling_mode, self.__enter_ums_scheduling_mode_arguments],
            'EnumResourceLanguagesA': [self.__enum_resource_languages_A, self.__enum_resource_languages_A_arguments],
            'EnumResourceLanguagesW': [self.__enum_resource_languages_A, self.__enum_resource_languages_A_arguments],
            'EnumResourceNamesA': [self.__enum_resource_names_A, self.__enum_resource_names_A_arguments],
            'EnumResourceTypesA': [self.__enum_resource_types_A, self.__enum_resource_types_A_arguments],
            'EnumResourceTypesW': [self.__enum_resource_types_A, self.__enum_resource_types_A_arguments],
            'EraseTape': [self.__erase_tape, self.__erase_tape_arguments],
            'EscapeCommFunction': [self.__escape_comm_function, self.__escape_comm_function_arguments],
            'ExecuteUmsThread': [self.__execute_ums_thread, self.__execute_ums_thread_arguments],
            'FatalExit': [self.__fatal_exit, self.__fatal_exit_arguments],
            'FileEncryptionStatusA': [self.__file_encryption_status_A, self.__file_encryption_status_A_arguments],
            'FileEncryptionStatusW': [self.__file_encryption_status_A, self.__file_encryption_status_A_arguments],
            'FileTimeToDosDateTime': [self.__file_time_to_dos_date_time, self.__file_time_to_dos_date_time_arguments],
            'FindActCtxSectionGuid': [self.__find_act_ctx_section_guid, self.__find_act_ctx_section_guid_arguments],
            'FindActCtxSectionStringA': [self.__find_act_ctx_section_string_A, self.__find_act_ctx_section_string_A_arguments],
            'FindActCtxSectionStringW': [self.__find_act_ctx_section_string_A, self.__find_act_ctx_section_string_A_arguments],
            'FindAtomA': [self.__find_atom_A, self.__find_atom_A_arguments],
            'FindAtomW': [self.__find_atom_A, self.__find_atom_A_arguments],
            'FindFirstFileNameTransactedW': [self.__find_first_file_name_transacted_W, self.__find_first_file_name_transacted_W_arguments],
            'FindFirstFileTransactedA': [self.__find_first_file_transacted_A, self.__find_first_file_transacted_A_arguments],
            'FindFirstFileTransactedW': [self.__find_first_file_transacted_A, self.__find_first_file_transacted_A_arguments],
            'FindFirstStreamTransactedW': [self.__find_first_stream_transacted_W, self.__find_first_stream_transacted_W_arguments],
            'FindFirstVolumeA': [self.__find_first_volume_A, self.__find_first_volume_A_arguments],
            'FindFirstVolumeMountPointA': [self.__find_first_volume_mount_pointA, self.__find_first_volume_mount_pointA_arguments],
            'FindFirstVolumeMountPointW': [self.__find_first_volume_mount_pointA, self.__find_first_volume_mount_pointA_arguments],
            'FindNextVolumeA': [self.__find_next_volume_A, self.__find_next_volume_A_arguments],
            'FindNextVolumeMountPointA': [self.__find_next_volume_mount_point_A, self.__find_next_volume_mount_point_A_arguments],
            'FindNextVolumeMountPointW': [self.__find_next_volume_mount_point_A, self.__find_next_volume_mount_point_A_arguments],
            'FindResourceA': [self.__find_resource_A, self.__find_resource_A_arguments],
            'FindResourceExA': [self.__find_resource_ex_A, self.__find_resource_ex_A_arguments],
            'FindVolumeMountPointClose': [self.__find_volume_mount_point_close, self.__find_volume_mount_point_close_arguments],
            'FormatMessage': [self.__format_message, self.__format_message_arguments],
            'FormatMessageA': [self.__format_message_A, self.__format_message_A_arguments],
            'FormatMessageW': [self.__format_message_A, self.__format_message_A_arguments],
            'GetActiveProcessorCount': [self.__get_active_processor_count, self.__get_active_processor_count_arguments],
            'GetActiveProcessorGroupCount': [self.__get_active_processor_group_count, self.__get_active_processor_group_count_arguments],
            'GetApplicationRecoveryCallback': [self.__get_application_recovery_callback, self.__get_application_recovery_callback_arguments],
            'GetApplicationRestartSettings': [self.__get_application_restart_settings, self.__get_application_restart_settings_arguments],
            'GetAtomNameA': [self.__get_atom_name_A, self.__get_atom_name_A_arguments],
            'GetAtomNameW': [self.__get_atom_name_A, self.__get_atom_name_A_arguments],
            'GetBinaryTypeA': [self.__get_binary_type_A, self.__get_binary_type_A_arguments],
            'GetBinaryTypeW': [self.__get_binary_type_A, self.__get_binary_type_A_arguments],
            'GetCommConfig': [self.__get_comm_config, self.__get_comm_config_arguments],
            'GetCommMask': [self.__get_comm_mask, self.__get_comm_mask_arguments],
            'GetCommModemStatus': [self.__get_comm_modem_status, self.__get_comm_modem_status_arguments],
            'GetCommPorts': [self.__get_comm_ports, self.__get_comm_ports_arguments],
            'GetCommProperties': [self.__get_comm_properties, self.__get_comm_properties_arguments],
            'GetCommState': [self.__get_comm_state, self.__get_comm_state_arguments],
            'GetCommTimeouts': [self.__get_comm_timeouts, self.__get_comm_timeouts_arguments],
            'GetCompressedFileSizeTransactedA': [self.__get_compressed_file_size_transacted_A, self.__get_compressed_file_size_transacted_A_arguments],
            'GetCompressedFileSizeTransactedW': [self.__get_compressed_file_size_transacted_A, self.__get_compressed_file_size_transacted_A_arguments],
            'GetComputerNameA': [self.__get_computer_name_A, self.__get_computer_name_A_arguments],
            'GetComputerNameW': [self.__get_computer_name_A, self.__get_computer_name_A_arguments],
            'GetCurrentActCtx': [self.__get_current_act_ctx, self.__get_current_act_ctx_arguments],
            'GetCurrentDirectory': [self.__get_current_directory, self.__get_current_directory_arguments],
            'GetCurrentHwProfileA': [self.__get_current_hw_profile_A, self.__get_current_hw_profile_A_arguments],
            'GetCurrentHwProfileW': [self.__get_current_hw_profile_A, self.__get_current_hw_profile_A_arguments],
            'GetCurrentUmsThread': [self.__get_current_ums_thread, self.__get_current_ums_thread_arguments],
            'GetDefaultCommConfigA': [self.__get_default_comm_config_A, self.__get_default_comm_config_A_arguments],
            'GetDefaultCommConfigW': [self.__get_default_comm_config_A, self.__get_default_comm_config_A_arguments],
            'GetDevicePowerState': [self.__get_device_power_state, self.__get_device_power_state_arguments],
            'GetDllDirectoryA': [self.__get_dll_directory_A, self.__get_dll_directory_A_arguments],
            'GetDllDirectoryW': [self.__get_dll_directory_A, self.__get_dll_directory_A_arguments],
            'GetEnabledXStateFeatures': [self.__get_enabled_x_state_features, self.__get_enabled_x_state_features_arguments],
            'GetEnvironmentVariable': [self.__get_environment_variable, self.__get_environment_variable_arguments],
            'GetEventLogInformation': [self.__get_event_log_information, self.__get_event_log_information_arguments],
            'GetFileAttributesTransactedA': [self.__get_file_attributes_transacted_A, self.__get_file_attributes_transacted_A_arguments],
            'GetFileAttributesTransactedW': [self.__get_file_attributes_transacted_A, self.__get_file_attributes_transacted_A_arguments],
            'GetFileBandwidthReservation': [self.__get_file_bandwidth_reservation, self.__get_file_bandwidth_reservation_arguments],
            'GetFileInformationByHandleEx': [self.__get_file_information_by_handle_ex, self.__get_file_information_by_handle_ex_arguments],
            'GetFileSecurityA': [self.__get_file_security_A, self.__get_file_security_A_arguments],
            'GetFirmwareEnvironmentVariableA': [self.__get_firmware_environment_variable_A, self.__get_firmware_environment_variable_A_arguments],
            'GetFirmwareEnvironmentVariableExA': [self.__get_firmware_environment_variable_ex_A, self.__get_firmware_environment_variable_ex_A_arguments],
            'GetFirmwareEnvironmentVariableExW': [self.__get_firmware_environment_variable_ex_A, self.__get_firmware_environment_variable_ex_A_arguments],
            'GetFirmwareEnvironmentVariableW': [self.__get_firmware_environment_variable_A, self.__get_firmware_environment_variable_A_arguments],
            'GetFirmwareType': [self.__get_firmware_type, self.__get_firmware_type_arguments],
            'GetFullPathNameTransactedA': [self.__get_full_path_name_transacted_A, self.__get_full_path_name_transacted_A_arguments],
            'GetFullPathNameTransactedW': [self.__get_full_path_name_transacted_A, self.__get_full_path_name_transacted_A_arguments],
            'GetLogicalDriveStringsA': [self.__get_logical_drive_strings_A, self.__get_logical_drive_strings_A_arguments],
            'GetLongPathNameTransactedA': [self.__get_long_path_name_transacted_A, self.__get_long_path_name_transacted_A_arguments],
            'GetLongPathNameTransactedW': [self.__get_long_path_name_transacted_A, self.__get_long_path_name_transacted_A_arguments],
            'GetMailslotInfo': [self.__get_mailslot_info, self.__get_mailslot_info_arguments],
            'GetMaximumProcessorCount': [self.__get_maximum_processor_count, self.__get_maximum_processor_count_arguments],
            'GetMaximumProcessorGroupCount': [self.__get_maximum_processor_group_count, self.__get_maximum_processor_group_count_arguments],
            'GetNamedPipeClientComputerNameA': [self.__get_named_pipe_client_computer_name_A, self.__get_named_pipe_client_computer_name_A_arguments],
            'GetNamedPipeClientProcessId': [self.__get_named_pipe_client_process_id, self.__get_named_pipe_client_process_id_arguments],
            'GetNamedPipeClientSessionId': [self.__get_named_pipe_client_session_id, self.__get_named_pipe_client_session_id_arguments],
            'GetNamedPipeHandleStateA': [self.__get_named_pipe_handle_state_A, self.__get_named_pipe_handle_state_A_arguments],
            'GetNamedPipeServerProcessId': [self.__get_named_pipe_server_process_id, self.__get_named_pipe_server_process_id_arguments],
            'GetNamedPipeServerSessionId': [self.__get_named_pipe_server_session_id, self.__get_named_pipe_server_session_id_arguments],
            'GetNextUmsListItem': [self.__get_next_ums_list_item, self.__get_next_ums_list_item_arguments],
            'GetNumaAvailableMemoryNode': [self.__get_numa_available_memory_node, self.__get_numa_available_memory_node_arguments],
            'GetNumaAvailableMemoryNodeEx': [self.__get_numa_available_memory_node_ex, self.__get_numa_available_memory_node_ex_arguments],
            'GetNumaNodeNumberFromHandle': [self.__get_numa_node_number_from_handle, self.__get_numa_node_number_from_handle_arguments],
            'GetNumaNodeProcessorMask': [self.__get_numa_node_processor_mask, self.__get_numa_node_processor_mask_arguments],
            'GetNumaProcessorNode': [self.__get_numa_processor_node, self.__get_numa_processor_node_arguments],
            'GetNumaProcessorNodeEx': [self.__get_numa_processor_node_ex, self.__get_numa_processor_node_ex_arguments],
            'GetNumaProximityNode': [self.__get_numa_proximity_node, self.__get_numa_proximity_node_arguments],
            'GetNumberOfEventLogRecords': [self.__get_number_of_event_log_records, self.__get_number_of_event_log_records_arguments],
            'GetOldestEventLogRecord': [self.__get_oldest_event_log_record, self.__get_oldest_event_log_record_arguments],
            'GetPrivateProfileInt': [self.__get_private_profile_int, self.__get_private_profile_int_arguments],
            'GetPrivateProfileIntA': [self.__get_private_profile_int_A, self.__get_private_profile_int_A_arguments],
            'GetPrivateProfileIntW': [self.__get_private_profile_int_A, self.__get_private_profile_int_A_arguments],
            'GetPrivateProfileSection': [self.__get_private_profile_section, self.__get_private_profile_section_arguments],
            'GetPrivateProfileSectionA': [self.__get_private_profile_section, self.__get_private_profile_section_arguments],
            'GetPrivateProfileSectionNames': [self.__get_private_profile_section_names, self.__get_private_profile_section_names_arguments],
            'GetPrivateProfileSectionNamesA': [self.__get_private_profile_section_names, self.__get_private_profile_section_names_arguments],
            'GetPrivateProfileSectionNamesW': [self.__get_private_profile_section_names, self.__get_private_profile_section_names_arguments],
            'GetPrivateProfileSectionW': [self.__get_private_profile_section, self.__get_private_profile_section_arguments],
            'GetPrivateProfileString': [self.__get_private_profile_string, self.__get_private_profile_string_arguments],
            'GetPrivateProfileStringA': [self.__get_private_profile_string, self.__get_private_profile_string_arguments],
            'GetPrivateProfileStringW': [self.__get_private_profile_string, self.__get_private_profile_string_arguments],
            'GetPrivateProfileStruct': [self.__get_private_profile_struct, self.__get_private_profile_struct_arguments],
            'GetPrivateProfileStructA': [self.__get_private_profile_struct, self.__get_private_profile_struct_arguments],
            'GetPrivateProfileStructW': [self.__get_private_profile_struct, self.__get_private_profile_struct_arguments],
            'GetProcessAffinityMask': [self.__get_process_affinity_mask, self.__get_process_affinity_mask_arguments],
            'GetProcessDEPPolicy': [self.__get_process_DEP_policy, self.__get_process_DEP_policy_arguments],
            'GetProcessIoCounters': [self.__get_process_io_counters, self.__get_process_io_counters_arguments],
            'GetProcessWorkingSetSize': [self.__get_process_working_set_size, self.__get_process_working_set_size_arguments],
            'GetProfileIntA': [self.__get_profile_int_A, self.__get_profile_int_A_arguments],
            'GetProfileIntW': [self.__get_profile_int_A, self.__get_profile_int_A_arguments],
            'GetProfileSectionA': [self.__get_profile_section_A, self.__get_profile_section_A_arguments],
            'GetProfileSectionW': [self.__get_profile_section_A, self.__get_profile_section_A_arguments],
            'GetProfileStringA': [self.__get_profile_string_A, self.__get_profile_string_A_arguments],
            'GetProfileStringW': [self.__get_profile_string_A, self.__get_profile_string_A_arguments],
            'GetShortPathNameA': [self.__get_short_path_name_A, self.__get_short_path_name_A_arguments],
            'GetSystemDEPPolicy': [self.__get_system_DEP_policy, self.__get_system_DEP_policy_arguments],
            'GetSystemPowerStatus': [self.__get_system_power_status, self.__get_system_power_status_arguments],
            'GetSystemRegistryQuota': [self.__get_system_registry_quota, self.__get_system_registry_quota_arguments],
            'GetTapeParameters': [self.__get_tape_parameters, self.__get_tape_parameters_arguments],
            'GetTapePosition': [self.__get_tape_position, self.__get_tape_position_arguments],
            'GetTapeStatus': [self.__get_tape_status, self.__get_tape_status_arguments],
            'GetTempFileName': [self.__get_temp_file_name, self.__get_temp_file_name_arguments],
            'GetThreadSelectorEntry': [self.__get_thread_selector_entry, self.__get_thread_selector_entry_arguments],
            'GetUmsCompletionListEvent': [self.__get_ums_completion_list_event, self.__get_ums_completion_list_event_arguments],
            'GetUmsSystemThreadInformation': [self.__get_ums_system_thread_information, self.__get_ums_system_thread_information_arguments],
            'GetUserNameA': [self.__get_user_name_A, self.__get_user_name_A_arguments],
            'GetUserNameW': [self.__get_user_name_A, self.__get_user_name_A_arguments],
            'GetVolumeNameForVolumeMountPointA': [self.__get_volume_name_for_volume_mount_point_A, self.__get_volume_name_for_volume_mount_point_A_arguments],
            'GetVolumePathNameA': [self.__get_volume_path_name_A, self.__get_volume_path_name_A_arguments],
            'GetVolumePathNamesForVolumeNameA': [self.__get_volume_path_names_for_volume_name_A, self.__get_volume_path_names_for_volume_name_A_arguments],
            'GetXStateFeaturesMask': [self.__get_X_state_features_mask, self.__get_X_state_features_mask_arguments],
            'GlobalAddAtomA': [self.__global_add_atom_A, self.__global_add_atom_A_arguments],
            'GlobalAddAtomExA': [self.__global_add_atom_ex_A, self.__global_add_atom_ex_A_arguments],
            'GlobalAddAtomExW': [self.__global_add_atom_ex_A, self.__global_add_atom_ex_A_arguments],
            'GlobalAddAtomW': [self.__global_add_atom_A, self.__global_add_atom_A_arguments],
            'GlobalAlloc': [self.__global_alloc, self.__global_alloc_arguments],
            'GlobalDeleteAtom': [self.__global_delete_atom, self.__global_delete_atom_arguments],
            'GlobalDiscard': [self.__global_discard, self.__global_discard_arguments],
            'GlobalFindAtomA': [self.__global_find_atom_A, self.__global_find_atom_A_arguments],
            'GlobalFindAtomW': [self.__global_find_atom_A, self.__global_find_atom_A_arguments],
            'GlobalFlags': [self.__global_flags, self.__global_flags_arguments],
            'GlobalFree': [self.__global_free, self.__global_free_arguments],
            'GlobalGetAtomNameA': [self.__global_get_atom_name_A, self.__global_get_atom_name_A_arguments],
            'GlobalGetAtomNameW': [self.__global_get_atom_name_A, self.__global_get_atom_name_A_arguments],
            'GlobalHandle': [self.__global_handle, self.__global_handle_arguments],
            'GlobalLock': [self.__global_lock, self.__global_lock_arguments],
            'GlobalMemoryStatus': [self.__global_memory_status, self.__global_memory_status_arguments],
            'GlobalReAlloc': [self.__global_re_alloc, self.__global_re_alloc_arguments],
            'GlobalSize': [self.__global_size, self.__global_size_arguments],
            'GlobalUnlock': [self.__global_unlock, self.__global_unlock_arguments],
            'HasOverlappedIoCompleted': [self.__has_overlapped_io_completed, self.__has_overlapped_io_completed_arguments],
            'InitAtomTable': [self.__init_atom_table, self.__init_atom_table_arguments],
            'InitializeContext': [self.__initialize_context, self.__initialize_context_arguments],
            'InitializeThreadpoolEnvironment': [self.__initialize_threadpool_environment, self.__initialize_threadpool_environment_arguments],
            'InterlockedExchangeSubtract': [self.__interlocked_exchange_subtract, self.__interlocked_exchange_subtract_arguments],
            'IsBadCodePtr': [self.__is_bad_code_ptr, self.__is_bad_code_ptr_arguments],
            'IsBadReadPtr': [self.__is_bad_read_ptr, self.__is_bad_read_ptr_arguments],
            'IsBadStringPtrA': [self.__is_bad_string_ptr_A, self.__is_bad_string_ptr_A_arguments],
            'IsBadStringPtrW': [self.__is_bad_string_ptr_A, self.__is_bad_string_ptr_A_arguments],
            'IsBadWritePtr': [self.__is_bad_write_ptr, self.__is_bad_write_ptr_arguments],
            'IsNativeVhdBoot': [self.__is_native_vhd_boot, self.__is_native_vhd_boot_arguments],
            'IsSystemResumeAutomatic': [self.__is_system_resume_automatic, self.__is_system_resume_automatic_arguments],
            'IsTextUnicode': [self.__is_text_unicode, self.__is_text_unicode_arguments],
            'LoadModule': [self.__load_module, self.__load_module_arguments],
            'LoadPackagedLibrary': [self.__load_packaged_library, self.__load_packaged_library_arguments],
            'LocalAlloc': [self.__local_alloc, self.__local_alloc_arguments],
            'LocalFlags': [self.__local_flags, self.__local_flags_arguments],
            'LocalFree': [self.__local_free, self.__local_free_arguments],
            'LocalHandle': [self.__local_handle, self.__local_handle_arguments],
            'LocalLock': [self.__local_lock, self.__local_lock_arguments],
            'LocalReAlloc': [self.__local_re_alloc, self.__local_re_alloc_arguments],
            'LocalSize': [self.__local_size, self.__local_size_arguments],
            'LocalUnlock': [self.__local_unlock, self.__local_unlock_arguments],
            'LocateXStateFeature': [self.__locate_X_state_feature, self.__locate_X_state_feature_arguments],
            'LogonUserA': [self.__logon_user_A, self.__logon_user_A_arguments],
            'LogonUserExA': [self.__logon_user_ex_A, self.__logon_user_ex_A_arguments],
            'LogonUserExW': [self.__logon_user_ex_A, self.__logon_user_ex_A_arguments],
            'LogonUserW': [self.__logon_user_A, self.__logon_user_A_arguments],
            'LookupAccountNameA': [self.__lookup_account_name_A, self.__lookup_account_name_A_arguments],
            'LookupAccountNameW': [self.__lookup_account_name_A, self.__lookup_account_name_A_arguments],
            'LookupAccountSidA': [self.__lookup_account_sid_A, self.__lookup_account_sid_A_arguments],
            'LookupAccountSidLocalA': [self.__lookup_account_sid_local_A, self.__lookup_account_sid_local_A_arguments],
            'LookupAccountSidLocalW': [self.__lookup_account_sid_local_A, self.__lookup_account_sid_local_A_arguments],
            'LookupAccountSidW': [self.__lookup_account_sid_A, self.__lookup_account_sid_A_arguments],
            'LookupPrivilegeDisplayNameA': [self.__lookup_privilege_display_name_A, self.__lookup_privilege_display_name_A_arguments],
            'LookupPrivilegeDisplayNameW': [self.__lookup_privilege_display_name_A, self.__lookup_privilege_display_name_A_arguments],
            'LookupPrivilegeNameA': [self.__lookup_privilege_name_A, self.__lookup_privilege_name_A_arguments],
            'LookupPrivilegeNameW': [self.__lookup_privilege_name_A, self.__lookup_privilege_name_A_arguments],
            'LookupPrivilegeValueA': [self.__lookup_privilege_value_A, self.__lookup_privilege_value_A_arguments],
            'LookupPrivilegeValueW': [self.__lookup_privilege_value_A, self.__lookup_privilege_value_A_arguments],
            'LpprogressRoutine': [self.__lpprogress_routine, self.__lpprogress_routine_arguments],
            'lstrcatA': [self.__lstrcat_A, self.__lstrcat_A_arguments],
            'lstrcatW': [self.__lstrcat_A, self.__lstrcat_A_arguments],
            'lstrcmpA': [self.__lstrcmp_A, self.__lstrcmp_A_arguments],
            'lstrcmpiA': [self.__lstrcmpi_A, self.__lstrcmpi_A_arguments],
            'lstrcmpiW': [self.__lstrcmpi_A, self.__lstrcmpi_A_arguments],
            'lstrcmpW': [self.__lstrcmp_A, self.__lstrcmp_A_arguments],
            'lstrcpyA': [self.__lstrcpy_A, self.__lstrcpy_A_arguments],
            'lstrcpynA': [self.__lstrcpyn_A, self.__lstrcpyn_A_arguments],
            'lstrcpynW': [self.__lstrcpyn_A, self.__lstrcpyn_A_arguments],
            'lstrcpyW': [self.__lstrcpy_A, self.__lstrcpy_A_arguments],
            'lstrlenA': [self.__lstrlen_A, self.__lstrlen_A_arguments],
            'lstrlenW': [self.__lstrlen_A, self.__lstrlen_A_arguments],
            'MapUserPhysicalPagesScatter': [self.__map_user_physical_pages_scatter, self.__map_user_physical_pages_scatter_arguments],
            'MapViewOfFileExNuma': [self.__map_view_of_file_ex_numa, self.__map_view_of_file_ex_numa_arguments],
            'MoveFile': [self.__move_file, self.__move_file_arguments],
            'MoveFileA': [self.__move_file, self.__move_file_arguments],
            'MoveFileExA': [self.__move_file_ex_A, self.__move_file_ex_A_arguments],
            'MoveFileExW': [self.__move_file_ex_A, self.__move_file_ex_A_arguments],
            'MoveFileTransactedA': [self.__move_file_transacted_A, self.__move_file_transacted_A_arguments],
            'MoveFileTransactedW': [self.__move_file_transacted_A, self.__move_file_transacted_A_arguments],
            'MoveFileW': [self.__move_file, self.__move_file_arguments],
            'MoveFileWithProgressA': [self.__move_file_with_progress_A, self.__move_file_with_progress_A_arguments],
            'MoveFileWithProgressW': [self.__move_file_with_progress_A, self.__move_file_with_progress_A_arguments],
            'MulDiv': [self.__mul_div, self.__mul_div_arguments],
            'NotifyChangeEventLog': [self.__notify_change_event_log, self.__notify_change_event_log_arguments],
            'ObjectCloseAuditAlarmA': [self.__object_close_audit_alarm_A, self.__object_close_audit_alarm_A_arguments],
            'ObjectDeleteAuditAlarmA': [self.__object_delete_audit_alarm_A, self.__object_delete_audit_alarm_A_arguments],
            'ObjectOpenAuditAlarmA': [self.__object_open_audit_alarm_A, self.__object_open_audit_alarm_A_arguments],
            'ObjectPrivilegeAuditAlarmA': [self.__object_privilege_audit_alarm_A, self.__object_privilege_audit_alarm_A_arguments],
            'OpenBackupEventLogA': [self.__open_backup_event_log_A, self.__open_backup_event_log_A_arguments],
            'OpenBackupEventLogW': [self.__open_backup_event_log_A, self.__open_backup_event_log_A_arguments],
            'OpenCommPort': [self.__open_comm_port, self.__open_comm_port_arguments],
            'OpenEncryptedFileRawA': [self.__open_encrypted_file_raw_A, self.__open_encrypted_file_raw_A_arguments],
            'OpenEncryptedFileRawW': [self.__open_encrypted_file_raw_A, self.__open_encrypted_file_raw_A_arguments],
            'OpenEventLogA': [self.__open_event_log_A, self.__open_event_log_A_arguments],
            'OpenEventLogW': [self.__open_event_log_A, self.__open_event_log_A_arguments],
            'OpenFile': [self.__open_file, self.__open_file_arguments],
            'OpenFileById': [self.__open_file_by_id, self.__open_file_by_id_arguments],
            'OpenFileMappingA': [self.__open_file_mapping_A, self.__open_file_mapping_A_arguments],
            'OpenJobObjectA': [self.__open_job_object_A, self.__open_job_object_A_arguments],
            'OpenPrivateNamespaceA': [self.__open_private_namespace_A, self.__open_private_namespace_A_arguments],
            'OperationEnd': [self.__operation_end, self.__operation_end_arguments],
            'OperationStart': [self.__operation_start, self.__operation_start_arguments],
            'Pcopyfile2ProgressRoutine': [self.__pcopyfile2_progress_routine, self.__pcopyfile2_progress_routine_arguments],
            'PfeExportFunc': [self.__pfe_export_func, self.__pfe_export_func_arguments],
            'PfeImportFunc': [self.__pfe_import_func, self.__pfe_import_func_arguments],
            'PfiberStartRoutine': [self.__pfiber_start_routine, self.__pfiber_start_routine_arguments],
            'PowerClearRequest': [self.__power_clear_request, self.__power_clear_request_arguments],
            'PowerCreateRequest': [self.__power_create_request, self.__power_create_request_arguments],
            'PowerSetRequest': [self.__power_set_request, self.__power_set_request_arguments],
            'PrepareTape': [self.__prepare_tape, self.__prepare_tape_arguments],
            'PrivilegedServiceAuditAlarmA': [self.__privileged_service_audit_alarm_A, self.__privileged_service_audit_alarm_A_arguments],
            'PulseEvent': [self.__pulse_event, self.__pulse_event_arguments],
            'PurgeComm': [self.__purge_comm, self.__purge_comm_arguments],
            'QueryActCtxSettingsW': [self.__query_act_ctx_settings_W, self.__query_act_ctx_settings_W_arguments],
            'QueryActCtxW': [self.__query_act_ctx_W, self.__query_act_ctx_W_arguments],
            'QueryDosDeviceA': [self.__query_dos_device_A, self.__query_dos_device_A_arguments],
            'QueryFullProcessImageNameA': [self.__query_full_process_image_name_A, self.__query_full_process_image_name_A_arguments],
            'QueryFullProcessImageNameW': [self.__query_full_process_image_name_A, self.__query_full_process_image_name_A_arguments],
            'QueryThreadProfiling': [self.__query_thread_profiling, self.__query_thread_profiling_arguments],
            'QueryUmsThreadInformation': [self.__query_ums_thread_information, self.__query_ums_thread_information_arguments],
            'ReadDirectoryChangesExW': [self.__read_directory_changes_ex_W, self.__read_directory_changes_ex_W_arguments],
            'ReadDirectoryChangesW': [self.__read_directory_changes_W, self.__ReadDirectoryChangesW_arguments],
            'ReadEncryptedFileRaw': [self.__read_encrypted_file_raw, self.__read_encrypted_file_raw_arguments],
            'ReadEventLogA': [self.__read_event_log_A, self.__read_event_log_A_arguments],
            'ReadEventLogW': [self.__read_event_log_A, self.__read_event_log_A_arguments],
            'ReadThreadProfilingData': [self.__read_thread_profiling_data, self.__read_thread_profiling_data_arguments],
            'RegisterApplicationRecoveryCallback': [self.__register_application_recovery_callback, self.__register_application_recovery_callback_arguments],
            'RegisterApplicationRestart': [self.__register_application_restart, self.__register_application_restart_arguments],
            'RegisterEventSourceA': [self.__register_event_source_A, self.__register_event_source_A_arguments],
            'RegisterEventSourceW': [self.__register_event_source_A, self.__register_event_source_A_arguments],
            'RegisterWaitForSingleObject': [self.__register_wait_for_single_object, self.__register_wait_for_single_object_arguments],
            'ReleaseActCtx': [self.__release_act_ctx, self.__release_act_ctx_arguments],
            'RemoveDirectoryTransactedA': [self.__remove_directory_transacted_A, self.__remove_directory_transacted_A_arguments],
            'RemoveDirectoryTransactedW': [self.__remove_directory_transacted_A, self.__remove_directory_transacted_A_arguments],
            'RemoveSecureMemoryCacheCallback': [self.__remove_secure_memory_cache_callback, self.__remove_secure_memory_cache_callback_arguments],
            'ReOpenFile': [self.__re_open_file, self.__re_open_file_arguments],
            'ReplaceFileA': [self.__replace_file_A, self.__replace_file_A_arguments],
            'ReplaceFileW': [self.__replace_file_A, self.__replace_file_A_arguments],
            'ReportEventA': [self.__report_event_A, self.__report_event_A_arguments],
            'ReportEventW': [self.__report_event_A, self.__report_event_A_arguments],
            'RequestWakeupLatency': [self.__request_wakeup_latency, self.__request_wakeup_latency_arguments],
            'SetCommBreak': [self.__set_comm_break, self.__set_comm_break_arguments],
            'SetCommConfig': [self.__set_comm_config, self.__set_comm_config_arguments],
            'SetCommMask': [self.__set_comm_mask, self.__set_comm_mask_arguments],
            'SetCommState': [self.__set_comm_state, self.__set_comm_state_arguments],
            'SetCommTimeouts': [self.__set_comm_timeouts, self.__set_comm_timeouts_arguments],
            'SetCurrentDirectory': [self.__set_current_directory, self.__set_current_directory_arguments],
            'SetDefaultCommConfigA': [self.__set_default_comm_config_A, self.__set_default_comm_config_A_arguments],
            'SetDefaultCommConfigW': [self.__set_default_comm_config_A, self.__set_default_comm_config_A_arguments],
            'SetDllDirectoryA': [self.__set_dll_directory_A, self.__set_dll_directory_A_arguments],
            'SetDllDirectoryW': [self.__set_dll_directory_A, self.__set_dll_directory_A_arguments],
            'SetEnvironmentVariable': [self.__set_environment_variable, self.__set_environment_variable_arguments],
            'SetFileAttributesTransactedA': [self.__set_file_attributes_transacted_A, self.__set_file_attributes_transacted_A_arguments],
            'SetFileAttributesTransactedW': [self.__set_file_attributes_transacted_A, self.__set_file_attributes_transacted_A_arguments],
            'SetFileBandwidthReservation': [self.__set_file_bandwidth_reservation, self.__set_file_bandwidth_reservation_arguments],
            'SetFileCompletionNotificationModes': [self.__set_file_completion_notification_modes, self.__set_file_completion_notification_modes_arguments],
            'SetFileSecurityA': [self.__set_file_security_A, self.__set_file_security_A_arguments],
            'SetFileShortNameA': [self.__set_file_short_name_A, self.__set_file_short_name_A_arguments],
            'SetFileShortNameW': [self.__set_file_short_name_A, self.__set_file_short_name_A_arguments],
            'SetFirmwareEnvironmentVariableA': [self.__set_firmware_environment_variable_A, self.__set_firmware_environment_variable_A_arguments],
            'SetFirmwareEnvironmentVariableExA': [self.__set_firmware_environment_variable_ex_A, self.__set_firmware_environment_variable_ex_A_arguments],
            'SetFirmwareEnvironmentVariableExW': [self.__set_firmware_environment_variable_ex_A, self.__set_firmware_environment_variable_ex_A_arguments],
            'SetFirmwareEnvironmentVariableW': [self.__set_firmware_environment_variable_A, self.__set_firmware_environment_variable_A_arguments],
            'SetHandleCount': [self.__set_handle_count, self.__set_handle_count_arguments],
            'SetMailslotInfo': [self.__set_mailslot_info, self.__set_mailslot_info_arguments],
            'SetProcessAffinityMask': [self.__set_process_affinity_mask, self.__set_process_affinity_mask_arguments],
            'SetProcessDEPPolicy': [self.__set_process_DEP_policy, self.__set_process_DEP_policy_arguments],
            'SetProcessWorkingSetSize': [self.__set_process_working_set_size, self.__set_process_working_set_size_arguments],
            'SetSearchPathMode': [self.__set_search_path_mode, self.__set_search_path_mode_arguments],
            'SetSystemPowerState': [self.__set_system_power_state, self.__set_system_power_state_arguments],
            'SetTapeParameters': [self.__set_tape_parameters, self.__set_tape_parameters_arguments],
            'SetTapePosition': [self.__set_tape_position, self.__set_tape_position_arguments],
            'SetThreadAffinityMask': [self.__set_thread_affinity_mask, self.__set_thread_affinity_mask_arguments],
            'SetThreadExecutionState': [self.__set_thread_execution_state, self.__set_thread_execution_state_arguments],
            'SetThreadpoolCallbackCleanupGroup': [self.__set_threadpool_callback_cleanup_group, self.__set_threadpool_callback_cleanup_group_arguments],
            'SetThreadpoolCallbackLibrary': [self.__set_threadpool_callback_library, self.__set_threadpool_callback_library_arguments],
            'SetThreadpoolCallbackPersistent': [self.__set_threadpool_callback_persistent, self.__set_threadpool_callback_persistent_arguments],
            'SetThreadpoolCallbackPool': [self.__set_threadpool_callback_pool, self.__set_threadpool_callback_pool_arguments],
            'SetThreadpoolCallbackPriority': [self.__set_threadpool_callback_priority, self.__set_threadpool_callback_priority_arguments],
            'SetThreadpoolCallbackRunsLong': [self.__set_threadpool_callback_runs_long, self.__set_threadpool_callback_runs_long_arguments],
            'SetUmsThreadInformation': [self.__set_ums_thread_information, self.__set_ums_thread_information_arguments],
            'SetupComm': [self.__setup_comm, self.__setup_comm_arguments],
            'SetVolumeLabelA': [self.__set_volume_label_A, self.__set_volume_label_A_arguments],
            'SetVolumeLabelW': [self.__set_volume_label_A, self.__set_volume_label_A_arguments],
            'SetVolumeMountPointA': [self.__set_volume_mount_point_A, self.__set_volume_mount_point_A_arguments],
            'SetVolumeMountPointW': [self.__set_volume_mount_point_A, self.__set_volume_mount_point_A_arguments],
            'SetXStateFeaturesMask': [self.__set_X_state_features_mask, self.__set_X_state_features_mask_arguments],
            'SwitchToFiber': [self.__switch_to_fiber, self.__switch_to_fiber_arguments],
            'TransmitCommChar': [self.__transmit_comm_char, self.__transmit_comm_char_arguments],
            'UmsThreadYield': [self.__ums_thread_yield, self.__ums_thread_yield_arguments],
            'UnregisterApplicationRecoveryCallback': [self.__unregister_application_recovery_callback, self.__unregister_application_recovery_callback_arguments],
            'UnregisterApplicationRestart': [self.__unregister_application_restart, self.__unregister_application_restart_arguments],
            'UnregisterWait': [self.__unregister_wait, self.__unregister_wait_arguments],
            'UpdateResourceA': [self.__update_resource_A, self.__update_resource_A_arguments],
            'UpdateResourceW': [self.__update_resource_A, self.__update_resource_A_arguments],
            'VerifyVersionInfoA': [self.__verify_version_info_A, self.__verify_version_info_A_arguments],
            'VerifyVersionInfoW': [self.__verify_version_info_A, self.__verify_version_info_A_arguments],
            'WaitCommEvent': [self.__wait_comm_event, self.__wait_comm_event_arguments],
            'WaitNamedPipeA': [self.__wait_named_pipe_A, self.__wait_named_pipe_A_arguments],
            'WinExec': [self.__win_exec, self.__win_exec_arguments],
            'WinMain': [self.__win_main, self.__win_main_arguments],
            'Wow64EnableWow64FsRedirection': [self.__wow64_enable_wow64_fs_redirection, self.__wow64_enable_wow64_fs_redirection_arguments],
            'Wow64GetThreadContext': [self.__wow64_get_thread_context, self.__wow64_get_thread_context_arguments],
            'Wow64GetThreadSelectorEntry': [self.__wow64_get_thread_selector_entry, self.__wow64_get_thread_selector_entry_arguments],
            'Wow64SetThreadContext': [self.__wow64_set_thread_context, self.__wow64_set_thread_context_arguments],
            'Wow64SuspendThread': [self.__wow64_suspend_thread, self.__wow64_suspend_thread_arguments],
            'WriteEncryptedFileRaw': [self.__write_encrypted_file_raw, self.__write_encrypted_file_raw_arguments],
            'WritePrivateProfileSectionA': [self.__write_private_profile_section_A, self.__write_private_profile_section_A_arguments],
            'WritePrivateProfileSectionW': [self.__write_private_profile_section_A, self.__write_private_profile_section_A_arguments],
            'WritePrivateProfileStringA': [self.__write_private_profile_string_A, self.__write_private_profile_string_A_arguments],
            'WritePrivateProfileStringW': [self.__write_private_profile_string_A, self.__write_private_profile_string_A_arguments],
            'WritePrivateProfileStructA': [self.__write_private_profile_struct_A, self.__write_private_profile_struct_A_arguments],
            'WritePrivateProfileStructW': [self.__write_private_profile_struct_A, self.__write_private_profile_struct_A_arguments],
            'WriteProfileSectionA': [self.__write_profile_section_A, self.__write_profile_section_A_arguments],
            'WriteProfileSectionW': [self.__write_profile_section_A, self.__write_profile_section_A_arguments],
            'WriteProfileStringA': [self.__write_profile_string_A, self.__write_profile_string_A_arguments],
            'WriteProfileStringW': [self.__write_profile_string_A, self.__write_profile_string_A_arguments],
            'WriteTapemark': [self.__write_tapemark, self.__write_tapemark_arguments],
            'WTSGetActiveConsoleSessionId': [self.__WTS_get_active_console_session_id, self.__WTS_get_active_console_session_id_arguments],
            'ZombifyActCtx': [self.__zombify_act_ctx, self.__zombify_act_ctx_arguments],
        })

    __access_check_and_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.POINTED_VALUE),
        FunctionArgument('objectTypeName', FunctionArgument.STRING),
        FunctionArgument('objectName', FunctionArgument.STRING),
        FunctionArgument('securityDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('desiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('genericMapping', FunctionArgument.ADDRESS),
        FunctionArgument('objectCreation', FunctionArgument.NUMBER),
        FunctionArgument('grantedAccess', FunctionArgument.POINTED_VALUE),
        FunctionArgument('accessStatus', FunctionArgument.ADDRESS),
        FunctionArgument('pfGenerateOnClose', FunctionArgument.POINTED_VALUE)
    ]

    def __access_check_and_audit_alarm_A(self, subsystemName, handleId, objectTypeName, objectName, securityDescriptor, desiredAccess, genericMapping, objectCreation, grantedAccess, accessStatus, pfGenerateOnClose):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1, FunctionResult.NUMBER, accessStatus)
        ])

    __access_check_by_type_and_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.POINTED_VALUE),
        FunctionArgument('objectTypeName', FunctionArgument.STRING),
        FunctionArgument('objectName', FunctionArgument.STRING),
        FunctionArgument('securityDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('principalSelfSid', FunctionArgument.STRING),
        FunctionArgument('desiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('auditType', FunctionArgument.NUMBER),
        FunctionArgument('flags', FunctionArgument.NUMBER),
        FunctionArgument('objectTypeList', FunctionArgument.ADDRESS),
        FunctionArgument('objectTypeListLength', FunctionArgument.NUMBER),
        FunctionArgument('genericMapping', FunctionArgument.ADDRESS),
        FunctionArgument('objectCreation', FunctionArgument.NUMBER),
        FunctionArgument('grantedAccess', FunctionArgument.POINTED_VALUE),
        FunctionArgument('accessStatus', FunctionArgument.ADDRESS),
        FunctionArgument('pfGenerateOnClose', FunctionArgument.POINTED_VALUE)
    ]

    def __access_check_by_type_and_audit_alarm_A(self, subsystemName, handleId, objectTypeName, objectName, securityDescriptor, principalSelfSid, desiredAccess, auditType, flags, objectTypeList, objectTypeListLength, genericMapping, objectCreation, grantedAccess, accessStatus, pfGenerateOnClose):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1, FunctionResult.NUMBER, accessStatus)
        ])

    __access_check_by_type_result_list_and_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.POINTED_VALUE),
        FunctionArgument('objectTypeName', FunctionArgument.STRING),
        FunctionArgument('objectName', FunctionArgument.STRING),
        FunctionArgument('securityDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('principalSelfSid', FunctionArgument.STRING),
        FunctionArgument('desiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('auditType', FunctionArgument.NUMBER),
        FunctionArgument('flags', FunctionArgument.NUMBER),
        FunctionArgument('objectTypeList', FunctionArgument.ADDRESS),
        FunctionArgument('objectTypeListLength', FunctionArgument.NUMBER),
        FunctionArgument('genericMapping', FunctionArgument.ADDRESS),
        FunctionArgument('objectCreation', FunctionArgument.NUMBER),
        FunctionArgument('grantedAccess', FunctionArgument.POINTED_VALUE),
        FunctionArgument('accessStatusList', FunctionArgument.ADDRESS),
        FunctionArgument('pfGenerateOnClose', FunctionArgument.POINTED_VALUE)
    ]

    def __access_check_by_type_result_list_and_audit_alarm_A(self, subsystemName, handleId, objectTypeName, objectName, securityDescriptor, principalSelfSid, desiredAccess, auditType, flags, objectTypeList, objectTypeListLength, genericMapping, objectCreation, grantedAccess, accessStatusList, pfGenerateOnClose):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(0, FunctionResult.NUMBER, accessStatusList)
        ])

    __access_check_by_type_result_list_and_audit_alarm_by_handle_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.POINTED_VALUE),
        FunctionArgument('clientToken', FunctionArgument.ADDRESS),
        FunctionArgument('objectTypeName', FunctionArgument.STRING),
        FunctionArgument('objectName', FunctionArgument.STRING),
        FunctionArgument('securityDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('principalSelfSid', FunctionArgument.STRING),
        FunctionArgument('desiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('auditType', FunctionArgument.NUMBER),
        FunctionArgument('flags', FunctionArgument.NUMBER),
        FunctionArgument('objectTypeList', FunctionArgument.ADDRESS),
        FunctionArgument('objectTypeListLength', FunctionArgument.NUMBER),
        FunctionArgument('genericMapping', FunctionArgument.ADDRESS),
        FunctionArgument('objectCreation', FunctionArgument.NUMBER),
        FunctionArgument('grantedAccess', FunctionArgument.POINTED_VALUE),
        FunctionArgument('accessStatusList', FunctionArgument.ADDRESS),
        FunctionArgument('pfGenerateOnClose', FunctionArgument.POINTED_VALUE)
    ]

    def __access_check_by_type_result_list_and_audit_alarm_by_handle_A(self, subsystemName, handleId, clientToken, objectTypeName, objectName, securityDescriptor, principalSelfSid, desiredAccess, auditType, flags, objectTypeList, objectTypeListLength, genericMapping, objectCreation, grantedAccess, accessStatusList, pfGenerateOnClose):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(0, FunctionResult.NUMBER, accessStatusList)
        ])

    __activate_act_ctx_arguments = [
        FunctionArgument('hActCtx', FunctionArgument.ADDRESS),
        FunctionArgument('lpCookie', FunctionArgument.POINTED_VALUE)
    ]

    def __activate_act_ctx(self, hActCtx, lpCookie):
        return self._wrap_results(self._true_result())

    __add_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __add_atom_A(self, lpString):
        atom = self.__atoms_table.add_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __add_conditional_ace_arguments = [
        FunctionArgument('pAcl', FunctionArgument.ADDRESS),
        FunctionArgument('dwAceRevision', FunctionArgument.STRING),
        FunctionArgument('aceFlags', FunctionArgument.NUMBER),
        FunctionArgument('aceType', FunctionArgument.NUMBER),
        FunctionArgument('accessMask', FunctionArgument.NUMBER),
        FunctionArgument('pSid', FunctionArgument.STRING),
        FunctionArgument('conditionStr', FunctionArgument.STRING),
        FunctionArgument('returnLength', FunctionArgument.NUMBER)
    ]

    def __add_conditional_ace(self, pAcl, dwAceRevision, aceFlags, aceType, accessMask, pSid, conditionStr, returnLength):
        return self._wrap_results(self._true_result())

    __add_integrity_label_to_boundary_descriptor_arguments = [
        FunctionArgument('boundaryDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('integrityLabel', FunctionArgument.STRING),
    ]

    def __add_integrity_label_to_boundary_descriptor(self, boundaryDescriptor, integrityLabel):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __add_ref_act_ctx_arguments = [
        FunctionArgument('hActCtx', FunctionArgument.ADDRESS)
    ]

    def __add_ref_act_ctx(self, hActCtx):
        return self._wrap_results(None)

    __add_secure_memory_cache_callback_arguments = [
        FunctionArgument('pfnCallBack', FunctionArgument.ADDRESS)
    ]

    def __add_secure_memory_cache_callback(self, pfnCallBack):
        return self._wrap_results(self._true_result())

    __application_recovery_finished_arguments = [
        FunctionArgument('bSuccess', FunctionArgument.NUMBER)
    ]

    def __application_recovery_finished(self, bSuccess):
        return self._wrap_results(self._true_result())

    __application_recovery_in_progress_arguments = [
        FunctionArgument('pbCancelled', FunctionArgument.NUMBER)
    ]

    def __application_recovery_in_progress(self, pbCancelled):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __backup_event_log_A_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('lpBackupFileName', FunctionArgument.STRING)
    ]

    def __backup_event_log_A(self, hEventLog, lpBackupFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __backup_read_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpBuffer', FunctionArgument.STRING),
        FunctionArgument('nNumberOfBytesToRead', FunctionArgument.NUMBER),
        FunctionArgument('lpNumberOfBytesRead', FunctionArgument.ADDRESS),
        FunctionArgument('bAbort', FunctionArgument.NUMBER),
        FunctionArgument('bProcessSecurity', FunctionArgument.NUMBER),
        FunctionArgument('lpContext', FunctionArgument.ADDRESS)
    ]

    def __backup_read(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, bAbort, bProcessSecurity, lpContext):
        data = lpBuffer.encode()[:nNumberOfBytesToRead]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(len(data), FunctionResult.NUMBER, lpNumberOfBytesRead)
        ])

    __backup_seek_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('dwLowBytesToSeek', FunctionArgument.NUMBER),
        FunctionArgument('dwHighBytesToSeek', FunctionArgument.NUMBER),
        FunctionArgument('lpdwLowByteSeeked', FunctionArgument.ADDRESS),
        FunctionArgument('lpdwHighByteSeeked', FunctionArgument.ADDRESS),
        FunctionArgument('lpContext', FunctionArgument.ADDRESS),
    ]

    def __backup_seek(self, hFile, dwLowBytesToSeek, dwHighBytesToSeek, lpdwLowByteSeeked, lpdwHighByteSeeked, lpContext):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(dwLowBytesToSeek, FunctionResult.NUMBER, lpdwLowByteSeeked),
            FunctionResult(dwHighBytesToSeek, FunctionResult.NUMBER, lpdwHighByteSeeked),
        ])

    __backup_write_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpBuffer', FunctionArgument.STRING),
        FunctionArgument('nNumberOfBytesToWrite', FunctionArgument.NUMBER),
        FunctionArgument('lpNumberOfBytesWritten', FunctionArgument.ADDRESS),
        FunctionArgument('bAbort', FunctionArgument.NUMBER),
        FunctionArgument('bProcessSecurity', FunctionArgument.NUMBER),
        FunctionArgument('lpContext', FunctionArgument.ADDRESS)
    ]

    def __backup_write(self, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, bAbort, bProcessSecurity, lpContext):
        data = lpBuffer.encode()[:nNumberOfBytesToWrite]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(len(data), FunctionResult.NUMBER, lpNumberOfBytesWritten)
        ])

    __begin_update_resource_A_arguments = [
        FunctionArgument('pFileName', FunctionArgument.STRING),
        FunctionArgument('bDeleteExistingResources', FunctionArgument.NUMBER)
    ]

    def __begin_update_resource_A(self, pFileName, bDeleteExistingResources):
        if util.is_pe_file(pFileName):
            result = self._new_address_result()
        else:
            result = self._null_result()
        return self._wrap_results(result)

    __bind_io_completion_callback_arguments = [
        FunctionArgument('fileHandle', FunctionArgument.ADDRESS),
        FunctionArgument('function', FunctionArgument.ADDRESS),
        FunctionArgument('flags', FunctionArgument.NUMBER)
    ]

    def __bind_io_completion_callback(self, fileHandle, function, flags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __build_comm_DCBA_arguments = [
        FunctionArgument('lpDef', FunctionArgument.STRING),
        FunctionArgument('lpDCB', FunctionArgument.ADDRESS)
    ]

    def __build_comm_DCBA(self, lpDef, lpDCB):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __build_comm_DCB_and_timeouts_A_arguments = [
        FunctionArgument('lpDef', FunctionArgument.STRING),
        FunctionArgument('lpDCB', FunctionArgument.ADDRESS),
        FunctionArgument('lpCommTimeouts', FunctionArgument.ADDRESS)
    ]

    def __build_comm_DCB_and_timeouts_A(self):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __call_named_pipe_A_arguments = [
        FunctionArgument('lpNamedPipeName', FunctionArgument.STRING),
        FunctionArgument('lpInBuffer', FunctionArgument.STRING),
        FunctionArgument('nInBufferSize', FunctionArgument.NUMBER),
        FunctionArgument('lpOutBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nOutBufferSize', FunctionArgument.NUMBER),
        FunctionArgument('lpBytesRead', FunctionArgument.ADDRESS),
        FunctionArgument('nTimeOut', FunctionArgument.NUMBER)
    ]

    def __call_named_pipe_A(self, lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesRead, nTimeOut):
        data = lpInBuffer.encode()[:nInBufferSize]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(len(data), FunctionResult.NUMBER, lpBytesRead)
        ])

    __check_name_legal_DOS8Dot3_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpOemName', FunctionArgument.ADDRESS),
        FunctionArgument('OemNameSize', FunctionArgument.NUMBER),
        FunctionArgument('pbNameContainsSpaces', FunctionArgument.NUMBER),
        FunctionArgument('pbNameLegal', FunctionArgument.NUMBER)
    ]

    def __check_name_legal_DOS8Dot3_A(self, lpName, lpOemName, OemNameSize, pbNameContainsSpaces, pbNameLegal):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __clear_comm_break_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS)
    ]

    def __clear_comm_break(self, hFile):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __clear_comm_error_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpErrors', FunctionArgument.POINTED_VALUE),
        FunctionArgument('lpStat', FunctionArgument.ADDRESS)
    ]

    def __clear_comm_error(self, hFile, lpErrors, lpStat):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __clear_event_log_A_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('lpBackupFileName', FunctionArgument.STRING)
    ]

    def __clear_event_log_A(self, hEventLog, lpBackupFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __close_encrypted_file_raw_arguments = [
        FunctionArgument('pvContext', FunctionArgument.ADDRESS)
    ]

    def __close_encrypted_file_raw(self, pvContext):
        return self._wrap_results(None)

    __close_event_log_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS)
    ]

    def __close_event_log(self, hEventLog):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __comm_config_dialog_A_arguments = [
        FunctionArgument('lpszName', FunctionArgument.STRING),
        FunctionArgument('hWnd', FunctionArgument.ADDRESS),
        FunctionArgument('lpCC', FunctionArgument.ADDRESS)
    ]

    def __comm_config_dialog_A(self, lpszName, hWnd, lpCC):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __convert_fiber_to_thread_arguments = []

    def __convert_fiber_to_thread(self):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __convert_thread_to_fiber_arguments = [
        FunctionArgument('lpParameter', FunctionArgument.ADDRESS)
    ]

    def __convert_thread_to_fiber(self, lpParameter):
        return self._wrap_results(self._new_address_result())

    __convert_thread_to_fiber_ex_arguments = [
        FunctionArgument('lpParameter', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __convert_thread_to_fiber_ex(self, lpParameter, dwFlags):
        return self._wrap_results(self._new_address_result())

    __copy_context_arguments = [
        FunctionArgument('destination', FunctionArgument.ADDRESS),
        FunctionArgument('contextFlags', FunctionArgument.NUMBER),
        FunctionArgument('source', FunctionArgument.ADDRESS)
    ]

    def __copy_context(self, destination, contextFlags, source):
        return self._wrap_results(self._true_result())

    __copy_file_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING),
        FunctionArgument('bFailIfExists', FunctionArgument.NUMBER)
    ]

    def __copy_file(self, lpExistingFileName, lpNewFileName, bFailIfExists):
        if bFailIfExists and os.path.isfile(lpNewFileName):
            result = FunctionResult(0, FunctionResult.NUMBER)
        else:
            result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __copy_file_2_arguments = [
        FunctionArgument('pwszExistingFileName', FunctionArgument.STRING),
        FunctionArgument('pwszNewFileName', FunctionArgument.STRING),
        FunctionArgument('pExtendedParameters', FunctionArgument.ADDRESS)
    ]

    def __copy_file_2(self, pwszExistingFileName, pwszNewFileName, pExtendedParameters):
        return self._wrap_results(self._true_result())

    __copy_file_ex_A_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING),
        FunctionArgument('lpProgressRoutine', FunctionArgument.ADDRESS),
        FunctionArgument('lpData', FunctionArgument.ADDRESS),
        FunctionArgument('pbCancel', FunctionArgument.NUMBER),
        FunctionArgument('dwCopyFlags', FunctionArgument.NUMBER)
    ]

    def __copy_file_ex_A(self, lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __copy_file_transacted_A_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING),
        FunctionArgument('lpProgressRoutine', FunctionArgument.ADDRESS),
        FunctionArgument('lpData', FunctionArgument.ADDRESS),
        FunctionArgument('pbCancel', FunctionArgument.NUMBER),
        FunctionArgument('dwCopyFlags', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __copy_file_transacted_A(self, lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create__act_ctx_A_arguments = [
        FunctionArgument('pActCtx', FunctionArgument.ADDRESS)
    ]

    def __create__act_ctx_A(self, pActCtx):
        return self._wrap_results(self._new_address_result())

    __create_boundary_descriptor_A_arguments = [
        FunctionArgument('name', FunctionArgument.STRING),
        FunctionArgument('flags', FunctionArgument.NUMBER)
    ]

    def __create_boundary_descriptor_A(self, name, flags):
        return self._wrap_results(self._new_address_result())

    __create_directory_arguments = [
        FunctionArgument('lpPathName', FunctionArgument.STRING),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS)
    ]

    def __create_directory(self, lpPathName, lpSecurityAttributes):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_directory_ex_A_arguments = [
        FunctionArgument('lpTemplateDirectory', FunctionArgument.STRING),
        FunctionArgument('lpNewDirectory', FunctionArgument.STRING),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS)
    ]

    def __create_directory_ex_A(self, lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_directory_transacted_A_arguments = [
        FunctionArgument('lpTemplateDirectory', FunctionArgument.STRING),
        FunctionArgument('lpNewDirectory', FunctionArgument.STRING),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __create_directory_transacted_A(self, lpTemplateDirectory, lpNewDirectory, lpSecurityAttributes, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_fiber_arguments = [
        FunctionArgument('dwStackSize', FunctionArgument.NUMBER),
        FunctionArgument('lpStartAddress', FunctionArgument.ADDRESS),
        FunctionArgument('lpParameter', FunctionArgument.ADDRESS)
    ]

    def __create_fiber(self, dwStackSize, lpStartAddress, lpParameter):
        return self._wrap_results(self._new_address_result())

    __create_fiber_ex_arguments = [
        FunctionArgument('dwStackCommitSize', FunctionArgument.NUMBER),
        FunctionArgument('dwStackReserveSize', FunctionArgument.NUMBER),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpStartAddress', FunctionArgument.ADDRESS),
        FunctionArgument('lpParameter', FunctionArgument.ADDRESS)
    ]

    def __create_fiber_ex(self, dwStackCommitSize, dwStackReserveSize, dwFlags, lpStartAddress, lpParameter):
        return self._wrap_results(self._new_address_result())

    __create_file_mapping_A_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpFileMappingAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('flProtect', FunctionArgument.NUMBER),
        FunctionArgument('dwMaximumSizeHigh', FunctionArgument.NUMBER),
        FunctionArgument('dwMaximumSizeLow', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING)
    ]

    def __create_file_mapping_A(self, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName):
        return self._wrap_results(self._new_address_result())

    __create_file_mapping_numa_A_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpFileMappingAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('flProtect', FunctionArgument.NUMBER),
        FunctionArgument('dwMaximumSizeHigh', FunctionArgument.NUMBER),
        FunctionArgument('dwMaximumSizeLow', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('nndPreferred', FunctionArgument.NUMBER)
    ]

    def __create_file_mapping_numa_A(self, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, nndPreferred):
        return self._wrap_results(self._new_address_result())

    __create_file_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('dwShareMode', FunctionArgument.NUMBER),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('dwCreationDisposition', FunctionArgument.NUMBER),
        FunctionArgument('dwFlagsAndAttributes', FunctionArgument.NUMBER),
        FunctionArgument('hTemplateFile', FunctionArgument.ADDRESS),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS),
        FunctionArgument('pusMiniVersion', FunctionArgument.NUMBER),
        FunctionArgument('lpExtendedParameter', FunctionArgument.ADDRESS)
    ]

    def __create_file_transacted_A(self, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion, lpExtendedParameter):
        return self._wrap_results(self._new_address_result())

    __create_hard_link_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS)
    ]

    def __create_hard_link_A(self, lpFileName, lpExistingFileName, lpSecurityAttributes):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_hard_link_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __create_hard_link_transacted_A(self, lpFileName, lpExistingFileName, lpSecurityAttributes, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_job_object_A_arguments = [
        FunctionArgument('lpJobAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('lpName', FunctionArgument.STRING)
    ]

    def __create_job_object_A(self, lpJobAttributes, lpName):
        return self._wrap_results(self._new_address_result())

    __create_mailslot_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('nMaxMessageSize', FunctionArgument.NUMBER),
        FunctionArgument('lReadTimeout', FunctionArgument.NUMBER),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS)
    ]

    def __create_mailslot_A(self, lpName, nMaxMessageSize, lReadTimeout, lpSecurityAttributes):
        return self._wrap_results(self._new_address_result())

    __create_named_pipe_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('dwOpenMode', FunctionArgument.NUMBER),
        FunctionArgument('dwPipeMode', FunctionArgument.NUMBER),
        FunctionArgument('nMaxInstances', FunctionArgument.NUMBER),
        FunctionArgument('nOutBufferSize', FunctionArgument.NUMBER),
        FunctionArgument('nInBufferSize', FunctionArgument.NUMBER),
        FunctionArgument('nDefaultTimeOut', FunctionArgument.NUMBER),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.ADDRESS)
    ]

    def __create_named_pipe_A(self, lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes):
        return self._wrap_results(self._new_address_result())

    __create_private_namespace_A_arguments = [
        FunctionArgument('lpPrivateNamespaceAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('lpBoundaryDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('lpAliasPrefix', FunctionArgument.STRING)
    ]

    def __create_private_namespace_A(self, lpPrivateNamespaceAttributes, lpBoundaryDescriptor, lpAliasPrefix):
        return self._wrap_results(self._new_address_result())

    __create_process_with_logon_W_arguments = [
        FunctionArgument('lpUsername', FunctionArgument.STRING),
        FunctionArgument('lpDomain', FunctionArgument.STRING),
        FunctionArgument('lpPassword', FunctionArgument.STRING),
        FunctionArgument('dwLogonFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpApplicationName', FunctionArgument.STRING),
        FunctionArgument('lpCommandLine', FunctionArgument.STRING),
        FunctionArgument('dwCreationFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpEnvironment', FunctionArgument.ADDRESS),
        FunctionArgument('lpCurrentDirectory', FunctionArgument.STRING),
        FunctionArgument('lpStartupInfo', FunctionArgument.ADDRESS),
        FunctionArgument('lpProcessInformation', FunctionArgument.ADDRESS)
    ]

    def __create_process_with_logon_W(self, lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_process_with_token_W_arguments = [
        FunctionArgument('hToken', FunctionArgument.ADDRESS),
        FunctionArgument('dwLogonFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpApplicationName', FunctionArgument.STRING),
        FunctionArgument('lpCommandLine', FunctionArgument.STRING),
        FunctionArgument('dwCreationFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpEnvironment', FunctionArgument.ADDRESS),
        FunctionArgument('lpCurrentDirectory', FunctionArgument.STRING),
        FunctionArgument('lpStartupInfo', FunctionArgument.ADDRESS),
        FunctionArgument('lpProcessInformation', FunctionArgument.ADDRESS),
    ]

    def __create_process_with_token_W(self, hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_semaphore_A_arguments = [
        FunctionArgument('lpSemaphoreAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('lInitialCount', FunctionArgument.NUMBER),
        FunctionArgument('lMaximumCount', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING)
    ]

    def __create_semaphore_A(self, lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName):
        return self._wrap_results(self._new_address_result())

    __create_semaphore_ex_A_arguments = [
        FunctionArgument('lpSemaphoreAttributes', FunctionArgument.ADDRESS),
        FunctionArgument('lInitialCount', FunctionArgument.NUMBER),
        FunctionArgument('lMaximumCount', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER)
    ]

    def __create_semaphore_ex_A(self, lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags, dwDesiredAccess):
        return self._wrap_results(self._new_address_result())

    __create_symbolic_link_A_arguments = [
        FunctionArgument('lpSymlinkFileName', FunctionArgument.STRING),
        FunctionArgument('lpTargetFileName', FunctionArgument.STRING),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __create_symbolic_link_A(self, lpSymlinkFileName, lpTargetFileName, dwFlags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_symbolic_link_transacted_A_arguments = [
        FunctionArgument('lpSymlinkFileName', FunctionArgument.STRING),
        FunctionArgument('lpTargetFileName', FunctionArgument.STRING),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __create_symbolic_link_transacted_A(self, lpSymlinkFileName, lpTargetFileName, dwFlags, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_tape_partition_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwPartitionMethod', FunctionArgument.NUMBER),
        FunctionArgument('dwCount', FunctionArgument.NUMBER),
        FunctionArgument('dwSize', FunctionArgument.NUMBER)
    ]

    def __create_tape_partition(self, hDevice, dwPartitionMethod, dwCount, dwSize):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __create_ums_completion_list_arguments = [
        FunctionArgument('umsCompletionList', FunctionArgument.ADDRESS)
    ]

    def __create_ums_completion_list(self, umsCompletionList):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=umsCompletionList)
        ])

    __create_ums_thread_context_arguments = [
        FunctionArgument('lpUmsThread', FunctionArgument.ADDRESS)
    ]

    def __create_ums_thread_context(self, lpUmsThread):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=lpUmsThread)
        ])

    __deactivate_act_ctx_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('ulCookie', FunctionArgument.ADDRESS)
    ]

    def __deactivate_act_ctx(self, dwFlags, ulCookie):
        return self._wrap_results(self._true_result())

    __debug_break_process_arguments = [
        FunctionArgument('process', FunctionArgument.ADDRESS)
    ]

    def __debug_break_process(self, process):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __debug_set_process_kill_on_exit_arguments = [
        FunctionArgument('killOnExit', FunctionArgument.NUMBER)
    ]

    def __debug_set_process_kill_on_exit(self, killOnExit):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __decrypt_file_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('dwReserved', FunctionArgument.NUMBER)
    ]

    def __decrypt_file_A(self, lpFileName, dwReserved):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __define_dos_device_A_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpDeviceName', FunctionArgument.STRING),
        FunctionArgument('lpTargetPath', FunctionArgument.STRING)
    ]

    def __define_dos_device_A(self, dwFlags, lpDeviceName, lpTargetPath):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_atom_arguments = [
        FunctionArgument('nAtom', FunctionArgument.NUMBER)
    ]

    def __delete_atom(self, nAtom):
        self.__atoms_table.remove_atom(nAtom)
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_fiber_arguments = [
        FunctionArgument('lpFiber', FunctionArgument.ADDRESS)
    ]

    def __delete_fiber(self, lpFiber):
        return self._wrap_results(None)

    __delete_file_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __delete_file(self, lpFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_file_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __delete_file_transacted_A(self, lpFileName, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_timer_queue_arguments = [
        FunctionArgument('timerQueue', FunctionArgument.ADDRESS)
    ]

    def __delete_timer_queue(self, timerQueue):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_ums_completion_list_arguments = [
        FunctionArgument('umsCompletionList', FunctionArgument.ADDRESS)
    ]

    def __delete_ums_completion_list(self, umsCompletionList):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_ums_thread_context_arguments = [
        FunctionArgument('umsThread', FunctionArgument.ADDRESS)
    ]

    def __delete_ums_thread_context(self, umsThread):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __delete_volume_mount_point_A_arguments = [
        FunctionArgument('lpszVolumeMountPoint', FunctionArgument.STRING)
    ]

    def __delete_volume_mount_point_A(self, lpszVolumeMountPoint):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __dequeue_ums_completion_list_items_arguments = [
        FunctionArgument('umsCompletionList', FunctionArgument.ADDRESS),
        FunctionArgument('waitTimeOut', FunctionArgument.NUMBER),
        FunctionArgument('umsThreadList', FunctionArgument.ADDRESS)
    ]

    def __dequeue_ums_completion_list_items(self, umsCompletionList, waitTimeOut, umsThreadList):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __deregister_event_source_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS)
    ]

    def __deregister_event_source(self, hEventLog):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __destroy_threadpool_environment_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS)
    ]

    def __destroy_threadpool_environment(self, pcbe):
        return self._wrap_results(None)

    __disable_thread_profiling_arguments = [
        FunctionArgument('performanceDataHandle', FunctionArgument.ADDRESS)
    ]

    def __disable_thread_profiling(self, performanceDataHandle):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __dns_hostname_to_computer_name_A_arguments = [
        FunctionArgument('hostname', FunctionArgument.STRING),
        FunctionArgument('computerName', FunctionArgument.STRING),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __dns_hostname_to_computer_name_A(self, hostname, computerName, nSize):
        data = hostname.encode()[:nSize]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=computerName),
            FunctionResult(len(data), FunctionResult.NUMBER, target=nSize)
        ])

    __dos_date_time_to_file_time_arguments = [
        FunctionArgument('wFatDate', FunctionArgument.NUMBER),
        FunctionArgument('wFatTime', FunctionArgument.NUMBER),
        FunctionArgument('lpFileTime', FunctionArgument.ADDRESS)
    ]

    def __dos_date_time_to_file_time(self, wFatDate, wFatTime, lpFileTime):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __enable_thread_profiling_arguments = [
        FunctionArgument('threadHandle', FunctionArgument.ADDRESS),
        FunctionArgument('flags', FunctionArgument.NUMBER),
        FunctionArgument('hardwareCounters', FunctionArgument.NUMBER),
        FunctionArgument('performanceDataHandle', FunctionArgument.ADDRESS)
    ]

    def __enable_thread_profiling(self, threadHandle, flags, hardwareCounters, performanceDataHandle):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __encrypt_file_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __encrypt_file_A(self, lpFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __end_update_resource_A_arguments = [
        FunctionArgument('hUpdate', FunctionArgument.ADDRESS),
        FunctionArgument('fDiscard', FunctionArgument.NUMBER)
    ]

    def __end_update_resource_A(self, hUpdate, fDiscard):
        return self._wrap_results(self._true_result())

    __enter_ums_scheduling_mode_arguments = [
        FunctionArgument('schedulerStartupInfo', FunctionArgument.ADDRESS)
    ]

    def __enter_ums_scheduling_mode(self, schedulerStartupInfo):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __enum_resource_languages_A_arguments = [
        FunctionArgument('hModule', FunctionArgument.ADDRESS),
        FunctionArgument('lpType', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpEnumFunc', FunctionArgument.ADDRESS),
        FunctionArgument('lParam', FunctionArgument.ADDRESS)
    ]

    def __enum_resource_languages_A(self, hModule, lpType, lpName, lpEnumFunc, lParam):
        return self._wrap_results(self._true_result())

    __enum_resource_names_A_arguments = [
        FunctionArgument('hModule', FunctionArgument.ADDRESS),
        FunctionArgument('lpType', FunctionArgument.NUMBER),
        FunctionArgument('lpEnumFunc', FunctionArgument.ADDRESS),
        FunctionArgument('lParam', FunctionArgument.ADDRESS)
    ]

    def __enum_resource_names_A(self, hModule, lpType, lpEnumFunc, lParam):
        return self._wrap_results(self._true_result())

    __enum_resource_types_A_arguments = [
        FunctionArgument('hModule', FunctionArgument.ADDRESS),
        FunctionArgument('lpEnumFunc', FunctionArgument.ADDRESS),
        FunctionArgument('lParam', FunctionArgument.ADDRESS)
    ]

    def __enum_resource_types_A(self, hModule, lpEnumFunc, lParam):
        return self._wrap_results(self._true_result())

    __erase_tape_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwEraseType', FunctionArgument.NUMBER),
        FunctionArgument('bImmediate', FunctionArgument.NUMBER)
    ]

    def __erase_tape(self, hDevice, dwEraseType, bImmediate):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __escape_comm_function_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('dwFunc', FunctionArgument.NUMBER)
    ]

    def __escape_comm_function(self, hFile, dwFunc):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __execute_ums_thread_arguments = [
        FunctionArgument('umsThread', FunctionArgument.ADDRESS)
    ]

    def __execute_ums_thread(self, umsThread):
        self._wrap_results(None)

    __fatal_exit_arguments = [
        FunctionArgument('exitCode', FunctionArgument.NUMBER)
    ]

    def __fatal_exit(self, exitCode):
        return self._wrap_results(None)

    __file_encryption_status_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('lpStatus', FunctionArgument.NUMBER)
    ]

    def __file_encryption_status_A(self, lpFileName, lpStatus):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(0, FunctionResult.NUMBER, target=lpFileName)
        ])

    __file_time_to_dos_date_time_arguments = [
        FunctionArgument('lpFileTime', FunctionArgument.ADDRESS),
        FunctionArgument('lpFatDate', FunctionArgument.NUMBER),
        FunctionArgument('lpFatTime', FunctionArgument.NUMBER)
    ]

    def __file_time_to_dos_date_time(self, lpFileTime, lpFatDate, lpFatTime):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __find_act_ctx_section_guid_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpExtensionGuid', FunctionArgument.ADDRESS),
        FunctionArgument('ulSectionId', FunctionArgument.NUMBER),
        FunctionArgument('lpGuidToFind', FunctionArgument.ADDRESS),
        FunctionArgument('returnedData', FunctionArgument.ADDRESS)
    ]

    def __find_act_ctx_section_guid(self, dwFlags, lpExtensionGuid, ulSectionId, lpGuidToFind, returnedData):
        return self._wrap_results(self._true_result())

    __find_act_ctx_section_string_A_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpExtensionGuid', FunctionArgument.ADDRESS),
        FunctionArgument('ulSectionId', FunctionArgument.NUMBER),
        FunctionArgument('lpStringToFind', FunctionArgument.STRING),
        FunctionArgument('returnedData', FunctionArgument.ADDRESS)
    ]

    def __find_act_ctx_section_string_A(self, dwFlags, lpExtensionGuid, ulSectionId, lpStringToFind, returnedData):
        return self._wrap_results(self._true_result())

    __find_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __find_atom_A(self, lpString):
        atom = self.__atoms_table.find_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __find_first_file_name_transacted_W_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('stringLength', FunctionArgument.NUMBER),
        FunctionArgument('linkName', FunctionArgument.ADDRESS),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __find_first_file_name_transacted_W(self, lpFileName, dwFlags, stringLength, linkName, hTransaction):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(lpFileName.encode(), FunctionResult.BYTES, target=linkName)
        ])

    __find_first_file_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('fInfoLevelId', FunctionArgument.NUMBER),
        FunctionArgument('lpFindFileData', FunctionArgument.ADDRESS),
        FunctionArgument('fSearchOp', FunctionArgument.NUMBER),
        FunctionArgument('lpSearchFilter', FunctionArgument.ADDRESS),
        FunctionArgument('dwAdditionalFlags', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __find_first_file_transacted_A(self, lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, hTransaction):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(lpFileName.encode(), FunctionResult.BYTES, target=lpFindFileData)
        ])

    __find_first_stream_transacted_W_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('infoLevel', FunctionArgument.NUMBER),
        FunctionArgument('lpFindStreamData', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __find_first_stream_transacted_W(self, lpFileName, infoLevel, lpFindStreamData, dwFlags, hTransaction):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(lpFileName.encode(), FunctionResult.BYTES, target=lpFindStreamData)
        ])

    __find_first_volume_A_arguments = [
        FunctionArgument('lpszVolumeName', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER)
    ]

    def __find_first_volume_A(self, lpszVolumeName, cchBufferLength):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(b'\x00', FunctionResult.BYTES, target=lpszVolumeName)
        ])

    __find_first_volume_mount_pointA_arguments = [
        FunctionArgument('lpszRootPathName', FunctionArgument.STRING),
        FunctionArgument('lpszVolumeMountPoint', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER)
    ]

    def __find_first_volume_mount_pointA(self, lpszRootPathName, lpszVolumeMountPoint, cchBufferLength):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(b'\x00', FunctionResult.BYTES, target=lpszVolumeMountPoint)
        ])

    __find_next_volume_A_arguments = [
        FunctionArgument('hFindVolume', FunctionArgument.NUMBER),
        FunctionArgument('lpszVolumeName', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER)
    ]

    def __find_next_volume_A(self, hFindVolume, lpszVolumeName, cchBufferLength):
        result = FunctionResult(0, FunctionResult.NUMBER) # Fails to emulate that there's no more files
        return self._wrap_results(result)

    __find_next_volume_mount_point_A_arguments = [
        FunctionArgument('hFindVolumeMountPoint', FunctionArgument.NUMBER),
        FunctionArgument('lpszVolumeMountPoint', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER)
    ]

    def __find_next_volume_mount_point_A(self, hFindVolumeMountPoint, lpszVolumeMountPoint, cchBufferLength):
        result = FunctionResult(0, FunctionResult.NUMBER) # Fails to emulate that there's no more mounted folders
        return self._wrap_results(result)

    __find_resource_A_arguments = [
        FunctionArgument('hModule', FunctionArgument.ADDRESS),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpType', FunctionArgument.NUMBER)
    ]

    def __find_resource_A(self, hModule, lpName, lpType):
        return self._wrap_results(self._new_address_result())

    __find_resource_ex_A_arguments = [
        FunctionArgument('hModule', FunctionArgument.ADDRESS),
        FunctionArgument('lpType', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('wLanguage', FunctionArgument.NUMBER)
    ]

    def __find_resource_ex_A(self, hModule, lpType, lpName, wLanguage):
        return self._wrap_results(self._new_address_result())

    __find_volume_mount_point_close_arguments = [
        FunctionArgument('hFindVolumeMountPoint', FunctionArgument.NUMBER)
    ]

    def __find_volume_mount_point_close(self, hFindVolumeMountPoint):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __format_message_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpSource', FunctionArgument.ADDRESS),
        FunctionArgument('dwMessageId', FunctionArgument.NUMBER),
        FunctionArgument('dwLanguageId', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('arguments', FunctionArgument.ADDRESS)
    ]

    def __format_message(self, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, arguments):
        data = b'One formated string from FormatMessage function'[:nSize-1] # Fake message
        self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __format_message_A_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpSource', FunctionArgument.ADDRESS),
        FunctionArgument('dwMessageId', FunctionArgument.NUMBER),
        FunctionArgument('dwLanguageId', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('arguments', FunctionArgument.ADDRESS)
    ]

    def __format_message_A(self, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, arguments):
        data = b'One formated string from FormatMessageA function'[:nSize-1] # Fake message
        self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_active_processor_count_arguments = [
        FunctionArgument('groupNumber', FunctionArgument.NUMBER)
    ]

    def __get_active_processor_count(self, groupNumber):
        result = FunctionResult(3, FunctionResult.NUMBER) # Fake number
        return self._wrap_results(result)

    __get_active_processor_group_count_arguments = []

    def __get_active_processor_group_count(self):
        result = FunctionResult(3, FunctionResult.NUMBER) # Fake number
        return self._wrap_results(result)

    __get_application_recovery_callback_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('pRecoveryCallback', FunctionArgument.ADDRESS),
        FunctionArgument('ppvParameter', FunctionArgument.ADDRESS),
        FunctionArgument('pdwPingInterval', FunctionArgument.NUMBER),
        FunctionArgument('pdwFlags', FunctionArgument.NUMBER)
    ]

    def __get_application_recovery_callback(self, hProcess, pRecoveryCallback, ppvParameter, pdwPingInterval, pdwFlags):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_application_restart_settings_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('pwzCommandline', FunctionArgument.ADDRESS),
        FunctionArgument('pcchSize', FunctionArgument.NUMBER),
        FunctionArgument('pdwFlags', FunctionArgument.NUMBER)
    ]

    def __get_application_restart_settings(self, hProcess, pwzCommandline, pcchSize, pdwFlags):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_atom_name_A_arguments = [
        FunctionArgument('nAtom', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_atom_name_A(self, nAtom, lpBuffer, nSize):
        string = self.__atoms_table.find_string(nAtom)
        string = string.encode()[:nSize].strip(b'\x00')
        return self._wrap_results([
            FunctionResult(len(string), FunctionResult.NUMBER),
            FunctionResult(string, FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_binary_type_A_arguments = [
        FunctionArgument('lpApplicationName', FunctionArgument.STRING),
        FunctionArgument('lpBinaryType', FunctionArgument.ADDRESS)
    ]

    def __get_binary_type_A(self, lpApplicationName, lpBinaryType):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(0, FunctionResult.NUMBER, target=lpBinaryType) # 32-bit Windows-based application
        ])

    __get_comm_config_arguments = [
        FunctionArgument('hCommDev', FunctionArgument.ADDRESS),
        FunctionArgument('lpCC', FunctionArgument.ADDRESS),
        FunctionArgument('lpdwSize', FunctionArgument.NUMBER)
    ]

    def __get_comm_config(self, hCommDev, lpCC, lpdwSize):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=lpCC)
        ])

    __get_comm_mask_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpEvtMask', FunctionArgument.ADDRESS)
    ]

    def __get_comm_mask(self, hFile, lpEvtMask):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(4, FunctionResult.NUMBER, target=lpEvtMask) # EV_TXEMPTY last character was sent
        ])

    __get_comm_modem_status_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpModemStat', FunctionArgument.ADDRESS)
    ]

    def __get_comm_modem_status(self, hFile, lpModemStat):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(16, FunctionResult.NUMBER, target=lpModemStat) # EV_MS_CTS_ON CTS signal is on
        ])

    __get_comm_ports_arguments = [
        FunctionArgument('lpPortNumbers', FunctionArgument.ADDRESS),
        FunctionArgument('uPortNumbersCount', FunctionArgument.NUMBER),
        FunctionArgument('puPortNumbersFound', FunctionArgument.NUMBER)
    ]

    def __get_comm_ports(self, lpPortNumbers, uPortNumbersCount, puPortNumbersFound):
        return self._wrap_results([
            FunctionResult(0, FunctionResult.NUMBER),
            FunctionResult(0, FunctionResult.NUMBER, target=puPortNumbersFound) # No common ports defined
        ])

    __get_comm_properties_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpCommProp', FunctionArgument.ADDRESS)
    ]

    def __get_comm_properties(self, hFile, lpCommProp):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_comm_state_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpDCB', FunctionArgument.ADDRESS)
    ]

    def __get_comm_state(self, hFile, lpDCB):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_comm_timeouts_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpCommTimeouts', FunctionArgument.ADDRESS)
    ]

    def __get_comm_timeouts(self, hFile, lpCommTimeouts):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_compressed_file_size_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('lpFileSizeHigh', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __get_compressed_file_size_transacted_A(self, lpFileName, lpFileSizeHigh, hTransaction):
        return self._wrap_results([
            FunctionResult(102400, FunctionResult.NUMBER), # fake size 100MB
            self._null_result(target=lpFileSizeHigh)
        ])

    __get_computer_name_A_arguments = [
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_computer_name_A(self, lpBuffer, nSize):
        data = b'my_computer_name'[:nSize-1] # fake computer name
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpBuffer),
            FunctionResult(len(data), FunctionResult.NUMBER, target=nSize)
        ])

    __get_current_act_ctx_arguments = [
        FunctionArgument('lphActCtx', FunctionArgument.ADDRESS)
    ]

    def __get_current_act_ctx(self, lphActCtx):
        return self._wrap_results([
            self._true_result(),
            self._new_address_result(target=lphActCtx)
        ])

    __get_current_directory_arguments = [
        FunctionArgument('nBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS)
    ]

    def __get_current_directory(self, nBufferLength, lpBuffer):
        data = os.getcwd().encode()[:nBufferLength-1]
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_current_hw_profile_A_arguments = [
        FunctionArgument('lpHwProfileInfo', FunctionArgument.ADDRESS)
    ]

    def __get_current_hw_profile_A(self, lpHwProfileInfo):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_current_ums_thread_arguments = []

    def __get_current_ums_thread(self):
        return self._wrap_results(self._new_address_result())

    __get_default_comm_config_A_arguments = [
        FunctionArgument('lpszName', FunctionArgument.STRING),
        FunctionArgument('lpCC', FunctionArgument.ADDRESS),
        FunctionArgument('lpdwSize', FunctionArgument.NUMBER)
    ]

    def __get_default_comm_config_A(self, lpszName, lpCC, lpdwSize):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=lpCC)
        ])

    __get_device_power_state_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('pfOn', FunctionArgument.ADDRESS)
    ]

    def __get_device_power_state(self, hDevice, pfOn):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._true_result(target=pfOn)
        ])

    __get_dll_directory_A_arguments = [
        FunctionArgument('nBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS)
    ]

    def __get_dll_directory_A(self, nBufferLength, lpBuffer):
        data = os.getcwd().encode() # fake dll directory - current path
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data[:nBufferLength-1] + b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_enabled_x_state_features_arguments = []

    def __get_enabled_x_state_features(self):
        result = FunctionResult(int('0x11111111', 16), FunctionResult.NUMBER) # fake all features
        return self._wrap_results(result)

    __get_environment_variable_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_environment_variable(self, lpName, lpBuffer, nSize):
        data = b'one_environment_value' # fake environment value
        return self._wrap_results([
            FunctionResult(len(data)+1, FunctionResult.NUMBER),
            FunctionResult(data[:nSize-1] + b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_event_log_information_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('dwInfoLevel', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('cbBufSize', FunctionArgument.NUMBER),
        FunctionArgument('pcbBytesNeeded', FunctionArgument.NUMBER)
    ]

    def __get_event_log_information(self, hEventLog, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded):
        data = b'some log information'
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data[:cbBufSize-1] + b'x\00', FunctionResult.BYTES, target=lpBuffer),
            FunctionResult(len(data)+1, FunctionResult.NUMBER, target=pcbBytesNeeded)
        ])

    __get_file_attributes_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('fInfoLevelId', FunctionArgument.NUMBER),
        FunctionArgument('lpFileInformation', FunctionArgument.ADDRESS),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __get_file_attributes_transacted_A(self, lpFileName, fInfoLevelId, lpFileInformation, hTransaction):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=lpFileInformation)
        ])

    __get_file_bandwidth_reservation_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpPeriodMilliseconds', FunctionArgument.ADDRESS),
        FunctionArgument('lpBytesPerPeriod', FunctionArgument.ADDRESS),
        FunctionArgument('pDiscardable', FunctionArgument.NUMBER),
        FunctionArgument('lpTransferSize', FunctionArgument.NUMBER),
        FunctionArgument('lpNumOutstandingRequests', FunctionArgument.NUMBER)
    ]

    def __get_file_bandwidth_reservation(self, hFile, lpPeriodMilliseconds, lpBytesPerPeriod, pDiscardable, lpTransferSize, lpNumOutstandingRequests):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(100, FunctionResult.NUMBER, target=lpPeriodMilliseconds), # fake 100 milliseconds per period
            FunctionResult(1024, FunctionResult.NUMBER, target=lpBytesPerPeriod), # fake 1KB per period
        ])

    __get_file_information_by_handle_ex_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('fileInformationClass', FunctionArgument.NUMBER),
        FunctionArgument('lpFileInformation', FunctionArgument.ADDRESS),
        FunctionArgument('dwBufferSize', FunctionArgument.NUMBER)
    ]

    def __get_file_information_by_handle_ex(self, hFile, fileInformationClass, lpFileInformation, dwBufferSize):
        data = b'some file information'[:dwBufferSize-1] + b'\x00'
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpFileInformation)
        ])

    __get_file_security_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('requestedInformation', FunctionArgument.NUMBER),
        FunctionArgument('pSecurityDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('nLength', FunctionArgument.NUMBER),
        FunctionArgument('lpnLengthNeeded', FunctionArgument.ADDRESS)
    ]

    def __get_file_security_A(self, lpFileName, requestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=pSecurityDescriptor),
            FunctionResult(nLength, FunctionResult.NUMBER, target=lpnLengthNeeded)
        ])

    __get_firmware_environment_variable_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpGuid', FunctionArgument.STRING),
        FunctionArgument('pBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_firmware_environment_variable_A(self, lpName, lpGuid, pBuffer, nSize):
        data = b'one_firmware_environment_variable'[:nSize-1] + b'\x00'
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=pBuffer)
        ])

    __get_firmware_environment_variable_ex_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpGuid', FunctionArgument.STRING),
        FunctionArgument('pBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('pdwAttribubutes', FunctionArgument.NUMBER)
    ]

    def __get_firmware_environment_variable_ex_A(self, lpName, lpGuid, pBuffer, nSize, pdwAttribubutes):
        data = b'one_firmware_environment_variable'[:nSize-1] + b'\x00'
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=pBuffer)
        ])

    __get_firmware_type_arguments = [
        FunctionArgument('firmwareType', FunctionArgument.ADDRESS)
    ]

    def __get_firmware_type(self, firmwareType):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_full_path_name_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('nBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('lpFilePart', FunctionArgument.ADDRESS),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __get_full_path_name_transacted_A(self, lpFileName, nBufferLength, lpBuffer, lpFilePart, hTransaction):
        data = f'{os.getcwd()}\\{lpFileName}'.encode()[:nBufferLength-1] # fake data diretory\file
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpBuffer),
            FunctionResult(lpFileName.encode() + b'\x00', FunctionResult.BYTES, target=lpFilePart)
        ])

    __get_logical_drive_strings_A_arguments = [
        FunctionArgument('nBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS)
    ]

    def __get_logical_drive_strings_A(self, nBufferLength, lpBuffer):
        data = b'C:\\'
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_long_path_name_transacted_A_arguments = [
        FunctionArgument('lpszShortPath', FunctionArgument.STRING),
        FunctionArgument('lpszLongPath', FunctionArgument.ADDRESS),
        FunctionArgument('cchBuffer', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __get_long_path_name_transacted_A(self, lpszShortPath, lpszLongPath, cchBuffer, hTransaction):
        data = lpszShortPath.encode()
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data[:cchBuffer-1] + b'\x00', FunctionResult.BYTES, target=lpszLongPath)
        ])

    __get_mailslot_info_arguments = [
        FunctionArgument('hMailslot', FunctionArgument.ADDRESS),
        FunctionArgument('lpMaxMessageSize', FunctionArgument.NUMBER),
        FunctionArgument('lpNextSize', FunctionArgument.NUMBER),
        FunctionArgument('lpMessageCount', FunctionArgument.NUMBER),
        FunctionArgument('lpReadTimeout', FunctionArgument.NUMBER)
    ]

    def __get_mailslot_info(self, hMailslot, lpMaxMessageSize, lpNextSize, lpMessageCount, lpReadTimeout):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_maximum_processor_count_arguments = [
        FunctionArgument('groupNumber', FunctionArgument.NUMBER)
    ]

    def __get_maximum_processor_count(self, groupNumber):
        result = FunctionResult(2, FunctionArgument.NUMBER) # fake 2 maximum number of processors
        return self._wrap_results(result)

    __get_maximum_processor_group_count_arguments = []

    def __get_maximum_processor_group_count(self):
        result = FunctionResult(2, FunctionArgument.NUMBER) # fake 2 maximum number of processors groups
        return self._wrap_results(result)

    __get_named_pipe_client_computer_name_A_arguments = [
        FunctionArgument('pipe', FunctionArgument.ADDRESS),
        FunctionArgument('clientComputerName', FunctionArgument.STRING),
        FunctionArgument('clientComputerNameLength', FunctionArgument.NUMBER)
    ]

    def __get_named_pipe_client_computer_name_A(self, pipe, clientComputerName, clientComputerNameLength):
        data = clientComputerName.encode()[:clientComputerNameLength]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=pipe)
        ])

    __get_named_pipe_client_process_id_arguments = [
        FunctionArgument('pipe', FunctionArgument.ADDRESS),
        FunctionArgument('clientProcessId', FunctionArgument.NUMBER)
    ]

    def __get_named_pipe_client_process_id(self, pipe, clientProcessId):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(clientProcessId, FunctionResult.NUMBER, target=pipe)
        ])

    __get_named_pipe_client_session_id_arguments = [
        FunctionArgument('pipe', FunctionArgument.ADDRESS),
        FunctionArgument('clientSessionId', FunctionArgument.NUMBER)
    ]

    def __get_named_pipe_client_session_id(self, pipe, clientSessionId):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(clientSessionId, FunctionResult.NUMBER, target=pipe)
        ])

    __get_named_pipe_handle_state_A_arguments = [
        FunctionArgument('hNamedPipe', FunctionArgument.ADDRESS),
        FunctionArgument('lpState', FunctionArgument.NUMBER),
        FunctionArgument('lpCurInstances', FunctionArgument.ADDRESS),
        FunctionArgument('lpMaxCollectionCount', FunctionArgument.ADDRESS),
        FunctionArgument('lpCollectDataTimeout', FunctionArgument.ADDRESS),
        FunctionArgument('lpUserName', FunctionArgument.ADDRESS),
        FunctionArgument('nMaxUserNameSize', FunctionArgument.NUMBER)
    ]

    def __get_named_pipe_handle_state_A(self, hNamedPipe, lpState, lpCurInstances, lpMaxCollectionCount, lpCollectDataTimeout, lpUserName, nMaxUserNameSize):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_named_pipe_server_process_id_arguments = [
        FunctionArgument('pipe', FunctionArgument.ADDRESS),
        FunctionArgument('serverProcessId', FunctionArgument.NUMBER)
    ]

    def __get_named_pipe_server_process_id(self, pipe, serverProcessId):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(serverProcessId, FunctionResult.NUMBER, target=pipe)
        ])

    __get_named_pipe_server_session_id_arguments = [
        FunctionArgument('pipe', FunctionArgument.ADDRESS),
        FunctionArgument('serverSessionId', FunctionArgument.NUMBER)
    ]

    def __get_named_pipe_server_session_id(self, pipe, serverSessionId):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(serverSessionId, FunctionResult.NUMBER, target=pipe)
        ])

    __get_next_ums_list_item_arguments = [
        FunctionArgument('umsContext', FunctionArgument.ADDRESS)
    ]

    def __get_next_ums_list_item(self, umsContext):
        return self._wrap_results(self._new_address_result())

    __get_numa_available_memory_node_arguments = [
        FunctionArgument('node', FunctionArgument.NUMBER),
        FunctionArgument('availableBytes', FunctionArgument.NUMBER)
    ]

    def __get_numa_available_memory_node(self, node, availableBytes):
        result = FunctionResult(1024**3, FunctionResult.NUMBER) # fake 1GB
        return self._wrap_results(result)

    __get_numa_available_memory_node_ex_arguments = [
        FunctionArgument('node', FunctionArgument.NUMBER),
        FunctionArgument('availableBytes', FunctionArgument.NUMBER)
    ]

    def __get_numa_available_memory_node_ex(self, node, availableBytes):
        result = FunctionResult(1024**3, FunctionResult.NUMBER) # fake 1GB
        return self._wrap_results(result)

    __get_numa_node_number_from_handle_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('nodeNumber', FunctionArgument.ADDRESS)
    ]

    def __get_numa_node_number_from_handle(self, hFile, nodeNumber):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(3, FunctionResult.NUMBER, target=nodeNumber) # fake number of the NUMA node
        ])

    __get_numa_node_processor_mask_arguments = [
        FunctionArgument('node', FunctionArgument.NUMBER),
        FunctionArgument('processorMask', FunctionArgument.NUMBER)
    ]

    def __get_numa_node_processor_mask(self, node, processorMask):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_numa_processor_node_arguments = [
        FunctionArgument('processor', FunctionArgument.NUMBER),
        FunctionArgument('nodeNumber', FunctionArgument.NUMBER)
    ]

    def __get_numa_processor_node(self, processor, nodeNumber):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_numa_processor_node_ex_arguments = [
        FunctionArgument('processor', FunctionArgument.ADDRESS),
        FunctionArgument('nodeNumber', FunctionArgument.ADDRESS)
    ]

    def __get_numa_processor_node_ex(self, processor, nodeNumber):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1, FunctionResult.NUMBER, target=nodeNumber) # fake node number
        ])

    __get_numa_proximity_node_arguments = [
        FunctionArgument('proximityId', FunctionArgument.NUMBER),
        FunctionArgument('nodeNumber', FunctionArgument.NUMBER)
    ]

    def __get_numa_proximity_node(self, proximityId, nodeNumber):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_number_of_event_log_records_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('numberOfRecords', FunctionArgument.ADDRESS)
    ]

    def __get_number_of_event_log_records(self, hEventLog, numberOfRecords):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(10, FunctionResult.NUMBER, target=numberOfRecords) # fake number of records
        ])

    __get_oldest_event_log_record_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('oldestRecord', FunctionArgument.ADDRESS)
    ]

    def __get_oldest_event_log_record(self, hEventLog, oldestRecord):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1, FunctionResult.NUMBER, target=oldestRecord) # fake record number
        ])

    __get_private_profile_int_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('nDefault', FunctionArgument.NUMBER),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __get_private_profile_int(self, lpAppName, lpKeyName, nDefault, lpFileName):
        result = FunctionResult(3, FunctionResult.NUMBER) # fake key id
        return self._wrap_results(result)

    __get_private_profile_int_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('nDefault', FunctionArgument.NUMBER),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __get_private_profile_int_A(self, lpAppName, lpKeyName, nDefault, lpFileName):
        result = FunctionResult(3, FunctionResult.NUMBER) # fake key id
        return self._wrap_results(result)

    __get_private_profile_section_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpReturnedString', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __get_private_profile_section(self, lpAppName, lpReturnedString, nSize, lpFileName):
        data = b'profilekey1=profilevalue1\x00profilekey2=profilevalue2'[:nSize-2] # fake key-value data
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data+b'\x00\x00', FunctionResult.BYTES, target=lpReturnedString)
        ])

    __get_private_profile_section_names_arguments = [
        FunctionArgument('lpszReturnBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __get_private_profile_section_names(self, lpszReturnBuffer, nSize, lpFileName):
        data = b'profilename1\x00profilename2'[:nSize-2] # fake profile names
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data+b'\x00\x00', FunctionResult.BYTES, target=lpszReturnBuffer)
        ])

    __get_private_profile_string_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('lpDefault', FunctionArgument.STRING),
        FunctionArgument('lpReturnedString', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __get_private_profile_string(self, lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName):
        data = b'Key_value_from_get_private_profile_string'[:nSize-1]
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpReturnedString)
        ])

    __get_private_profile_struct_arguments = [
        FunctionArgument('lpszSection', FunctionArgument.STRING),
        FunctionArgument('lpszKey', FunctionArgument.STRING),
        FunctionArgument('lpStruct', FunctionArgument.ADDRESS),
        FunctionArgument('uSizeStruct', FunctionArgument.NUMBER),
        FunctionArgument('szFile', FunctionArgument.STRING)
    ]

    def __get_private_profile_struct(self, lpszSection, lpszKey, lpStruct, uSizeStruct, szFile):
        data = b'Some_data_from_file_section_and_keyname'[:uSizeStruct-1]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpStruct)
        ])

    __get_process_affinity_mask_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('lpProcessAffinityMask', FunctionArgument.ADDRESS),
        FunctionArgument('lpSystemAffinityMask', FunctionArgument.ADDRESS)
    ]

    def __get_process_affinity_mask(self, hProcess, lpProcessAffinityMask, lpSystemAffinityMask):
        affinity = int('0x11111111', 16) # fake max affinity
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(affinity, FunctionResult.NUMBER, target=lpProcessAffinityMask),
            FunctionResult(affinity, FunctionResult.NUMBER, target=lpSystemAffinityMask)
        ])

    __get_process_DEP_policy_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('lpFlags', FunctionArgument.ADDRESS),
        FunctionArgument('lpPermanent', FunctionArgument.NUMBER)
    ]

    def __get_process_DEP_policy(self, hProcess, lpFlags, lpPermanent):
        return self._wrap_results([
            self._true_result(),
            FunctionResult(0, FunctionResult.NUMBER, target=lpFlags) # fake DEP disabled
        ])

    __get_process_io_counters_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('lpIoCounters', FunctionArgument.ADDRESS)
    ]

    def __get_process_io_counters(self, hProcess, lpIoCounters):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_process_working_set_size_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('lpMinimumWorkingSetSize', FunctionArgument.ADDRESS),
        FunctionArgument('lpMaximumWorkingSetSize', FunctionArgument.ADDRESS)
    ]

    def __get_process_working_set_size(self, hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1024**2, FunctionResult.NUMBER, target=lpMinimumWorkingSetSize), # fake minimum working set size - 1MB
            FunctionResult(1024**3, FunctionResult.NUMBER, target=lpMaximumWorkingSetSize), # fake maximum working set size - 1GB
        ])

    __get_profile_int_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('nDefault', FunctionArgument.NUMBER)
    ]

    def __get_profile_int_A(self, lpAppName, lpKeyName, nDefault):
        result = FunctionResult(3, FunctionResult.NUMBER) # fake key id
        return self._wrap_results(result)

    __get_profile_section_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpReturnedString', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __get_profile_section_A(self, lpAppName, lpReturnedString, nSize):
        data = b'keyprofile1=keyvalue1\x00keyprofile2=keyvalue2'[:nSize - 2]
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data+b'\x00\x00', FunctionResult.BYTES, target=lpReturnedString)
        ])

    __get_profile_string_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('lpDefault', FunctionArgument.STRING),
        FunctionArgument('lpReturnedString', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]
    
    def __get_profile_string_A(self, lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize):
        data = b'Key_value_from_get_profile_string'[:nSize-1]
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpReturnedString)
        ])

    __get_short_path_name_A_arguments = [
        FunctionArgument('lpszLongPath', FunctionArgument.STRING),
        FunctionArgument('lpszShortPath', FunctionArgument.ADDRESS),
        FunctionArgument('cchBuffer', FunctionArgument.NUMBER)
    ]

    def __get_short_path_name_A(self, lpszLongPath, lpszShortPath, cchBuffer):
        data = lpszLongPath.encode()[:cchBuffer - 1]
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpszShortPath)
        ])

    __get_system_DEP_policy_arguments = []

    def __get_system_DEP_policy(self):
        result = FunctionResult(0, FunctionResult.NUMBER) # fake DEP is always off
        return self._wrap_results(result)

    __get_system_power_status_arguments = [
        FunctionArgument('lpSystemPowerStatus', FunctionArgument.ADDRESS)
    ]

    def __get_system_power_status(self, lpSystemPowerStatus):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_system_registry_quota_arguments = [
        FunctionArgument('pdwQuotaAllowed', FunctionArgument.ADDRESS),
        FunctionArgument('pdwQuotaUsed', FunctionArgument.ADDRESS)
    ]

    def __get_system_registry_quota(self, pdwQuotaAllowed, pdwQuotaUsed):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1024**3, FunctionResult.NUMBER, target=pdwQuotaAllowed), # fake 1GB size of registry allowed
            FunctionResult(200*(1024**2), FunctionResult.NUMBER, target=pdwQuotaUsed) # fake 200MB size of registry used
        ])

    __get_tape_parameters_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwOperation', FunctionArgument.NUMBER),
        FunctionArgument('lpdwSize', FunctionArgument.ADDRESS),
        FunctionArgument('lpTapeInformation', FunctionArgument.ADDRESS)
    ]

    def __get_tape_parameters(self, hDevice, dwOperation, lpdwSize, lpTapeInformation):
        result = FunctionResult(0, FunctionResult.NUMBER) # NO_ERROR
        return self._wrap_results(result)

    __get_tape_position_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwPositionType', FunctionArgument.NUMBER),
        FunctionArgument('lpdwPartition', FunctionArgument.ADDRESS),
        FunctionArgument('lpdwOffsetLow', FunctionArgument.ADDRESS),
        FunctionArgument('lpdwOffsetHigh', FunctionArgument.ADDRESS)
    ]

    def __get_tape_position(self, hDevice, dwPositionType, lpdwPartition, lpdwOffsetLow, lpdwOffsetHigh):
        return self._wrap_results([
            FunctionResult(0, FunctionResult.NUMBER),
            FunctionResult(2, FunctionResult.NUMBER, target=lpdwPartition), # fake 2nd partition
            FunctionResult(1024**3, FunctionResult.NUMBER, target=lpdwOffsetLow), # fake 1GB partition
            self._null_result(target=lpdwOffsetHigh)
        ])

    __get_tape_status_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS)
    ]

    def __get_tape_status(self, hDevice):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_temp_file_name_arguments = [
        FunctionArgument('lpPathName', FunctionArgument.STRING),
        FunctionArgument('lpPrefixString', FunctionArgument.STRING),
        FunctionArgument('uUnique', FunctionArgument.NUMBER),
        FunctionArgument('lpTempFileName', FunctionArgument.ADDRESS)
    ]

    def __get_temp_file_name(self, lpPathName, lpPrefixString, uUnique, lpTempFileName):
        number = uUnique or 1337
        data = f'{lpPrefixString[:3]}{lpPathName}{number}'.encode()
        return self._wrap_results([
            FunctionResult(number, FunctionResult.NUMBER),
            FunctionResult(data + b'\x00', FunctionResult.BYTES, target=lpTempFileName)
        ])

    __get_thread_selector_entry_arguments = [
        FunctionArgument('hThread', FunctionArgument.ADDRESS),
        FunctionArgument('dwSelector', FunctionArgument.NUMBER),
        FunctionArgument('lpSelectorEntry', FunctionArgument.ADDRESS)
    ]

    def __get_thread_selector_entry(self, hThread, dwSelector, lpSelectorEntry):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __get_ums_completion_list_event_arguments = [
        FunctionArgument('umsCompletionList', FunctionArgument.ADDRESS),
        FunctionArgument('umsCompletionEvent', FunctionArgument.ADDRESS)
    ]

    def __get_ums_completion_list_event(self, umsCompletionList, umsCompletionEvent):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=umsCompletionEvent)
        ])

    __get_ums_system_thread_information_arguments = [
        FunctionArgument('threadHandle', FunctionArgument.ADDRESS),
        FunctionArgument('systemThreadInfo', FunctionArgument.ADDRESS)
    ]

    def __get_ums_system_thread_information(self, threadHandle, systemThreadInfo):
        return self._wrap_results(self._true_result())

    __get_user_name_A_arguments = [
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('pcbBuffer', FunctionArgument.NUMBER)
    ]

    def __get_user_name_A(self, lpBuffer, pcbBuffer):
        data = b'one_username'[:pcbBuffer-1]
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpBuffer)
        ])

    __get_volume_name_for_volume_mount_point_A_arguments = [
        FunctionArgument('lpszVolumeMountPoint', FunctionArgument.STRING),
        FunctionArgument('lpszVolumeName', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER)
    ]

    def __get_volume_name_for_volume_mount_point_A(self, lpszVolumeMountPoint, lpszVolumeName, cchBufferLength):
        data = b'\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}'[:cchBufferLength-1] + b'\x00' # fake volume GUID
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpszVolumeName)
        ])

    __get_volume_path_name_A_arguments = [
        FunctionArgument('lpszFileName', FunctionArgument.STRING),
        FunctionArgument('lpszVolumePathName', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER)
    ]

    def __get_volume_path_name_A(self, lpszFileName, lpszVolumePathName, cchBufferLength):
        data = b'C:\\'[:cchBufferLength-1] + b'\x00' # fake volume path
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpszVolumePathName)
        ])

    __get_volume_path_names_for_volume_name_A_arguments = [
        FunctionArgument('lpszVolumeName', FunctionArgument.STRING),
        FunctionArgument('lpszVolumePathNames', FunctionArgument.ADDRESS),
        FunctionArgument('cchBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('lpcchReturnLength', FunctionArgument.ADDRESS)
    ]

    def __get_volume_path_names_for_volume_name_A(self, lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=lpszVolumePathNames)
        ])

    __get_X_state_features_mask_arguments = [
        FunctionArgument('context', FunctionArgument.ADDRESS),
        FunctionArgument('featureMask', FunctionArgument.ADDRESS)
    ]

    def __get_X_state_features_mask(self, context, featureMask):
        return self._wrap_results([
            self._true_result(),
            self._new_address_result(target=featureMask)
        ])

    __global_add_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __global_add_atom_A(self, lpString):
        atom = self.__atoms_table.add_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __global_add_atom_ex_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING),
        FunctionArgument('flags', FunctionArgument.NUMBER)
    ]

    def __global_add_atom_ex_A(self, lpString, flags):
        atom = self.__atoms_table.add_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __global_alloc_arguments = [
        FunctionArgument('uFlags', FunctionArgument.NUMBER),
        FunctionArgument('dwBytes', FunctionArgument.NUMBER)
    ]

    def __global_alloc(self, uFlags, dwBytes):
        result = FunctionResult(dwBytes, FunctionResult.NUMBER, to_reference=True) if dwBytes > 0 else self._new_address_result()
        return self._wrap_results(result)

    __global_delete_atom_arguments = [
        FunctionArgument('nAtom', FunctionArgument.NUMBER)
    ]

    def __global_delete_atom(self, nAtom):
        self.__atoms_table.remove_atom(nAtom)
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __global_discard_arguments = [
        FunctionArgument('h', FunctionArgument.ADDRESS)
    ]

    def __global_discard(self, h):
        return self._wrap_results(None)

    __global_find_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __global_find_atom_A(self, lpString):
        atom = self.__atoms_table.find_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __global_flags_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __global_flags(self, hMem):
        result = FunctionResult(int('0x11111111', 16), FunctionResult.NUMBER) # fake allocation values and lock count
        return self._wrap_results(result)

    __global_free_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __global_free(self, hMem):
        return self._wrap_results(self._null_result())

    __global_get_atom_name_A_arguments = [
        FunctionArgument('nAtom', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __global_get_atom_name_A(self, nAtom, lpBuffer, nSize):
        string = self.__atoms_table.find_string(nAtom)
        string = string.encode()[:nSize].strip(b'\x00')
        return self._wrap_results([
            FunctionResult(len(string), FunctionResult.NUMBER),
            FunctionResult(string, FunctionResult.BYTES, target=lpBuffer)
        ])

    __global_handle_arguments = [
        FunctionArgument('pMem', FunctionArgument.ADDRESS)
    ]

    def __global_handle(self, pMem):
        result = FunctionResult(int(pMem, 16), FunctionResult.NUMBER)
        return self._wrap_results(result)

    __global_lock_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __global_lock(self, hMem):
        result = FunctionResult(int(hMem, 16), FunctionResult.NUMBER)
        return self._wrap_results(result)

    __global_memory_status_arguments = [
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS)
    ]

    def __global_memory_status(self, lpBuffer):
        return self._wrap_results(None)

    __global_re_alloc_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS),
        FunctionArgument('dwBytes', FunctionArgument.NUMBER),
        FunctionArgument('uFlags', FunctionArgument.NUMBER)
    ]

    def __global_re_alloc(self, hMem, dwBytes, uFlags):
        result = FunctionResult(dwBytes, FunctionResult.NUMBER, to_reference=True)
        return self._wrap_results(result)

    __global_size_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __global_size(self, hMem):
        result = FunctionResult(10, FunctionResult.NUMBER) # fake 10 bytes of memory
        return self._wrap_results(result)

    __global_unlock_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __global_unlock(self, hMem):
        result = FunctionResult(0, FunctionResult.NUMBER) # memory object unlocked
        return self._wrap_results(result)

    __has_overlapped_io_completed_arguments = [
        FunctionArgument('lpOverlapped', FunctionArgument.ADDRESS)
    ]

    def __has_overlapped_io_completed(self, lpOverlapped):
        return self._wrap_results(None)

    __init_atom_table_arguments = [
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __init_atom_table(self, nSize):
        return self._wrap_results(self._true_result())

    __initialize_context_arguments = [
        FunctionArgument('buffer', FunctionArgument.ADDRESS),
        FunctionArgument('contextFlags', FunctionArgument.NUMBER),
        FunctionArgument('context', FunctionArgument.ADDRESS),
        FunctionArgument('contextLength', FunctionArgument.ADDRESS)
    ]

    def __initialize_context(self, buffer, contextFlags, context, contextLength):
        return self._wrap_results([
            self._true_result(),
            self._new_address_result(target=context),
            FunctionResult(1024**2, FunctionResult.NUMBER, target=contextLength) # fake 1MB context length
        ])

    __initialize_threadpool_environment_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS)
    ]

    def __initialize_threadpool_environment(self, pcbe):
        return self._wrap_results(None)

    __interlocked_exchange_subtract_arguments = [
        FunctionArgument('addend', FunctionArgument.ADDRESS),
        FunctionArgument('value', FunctionArgument.NUMBER)
    ]

    def __interlocked_exchange_subtract(self, addend, value):
        return self._wrap_results([
            FunctionResult(int(addend, 16), FunctionResult.NUMBER),
            FunctionResult(value, FunctionResult.NUMBER, target=addend)
        ])

    __is_bad_code_ptr_arguments = [
        FunctionArgument('lpfn', FunctionArgument.ADDRESS)
    ]

    def __is_bad_code_ptr(self, lpfn):
        result = FunctionResult(0, FunctionResult.NUMBER) # fake read access
        return self._wrap_results(result)

    __is_bad_read_ptr_arguments = [
        FunctionArgument('lp', FunctionArgument.ADDRESS),
        FunctionArgument('ucb', FunctionArgument.NUMBER)
    ]

    def __is_bad_read_ptr(self, lp, ucb):
        result = FunctionResult(0, FunctionResult.NUMBER) # fake read access
        return self._wrap_results(result)

    __is_bad_string_ptr_A_arguments = [
        FunctionArgument('lpsz', FunctionArgument.STRING),
        FunctionArgument('ucchMax', FunctionArgument.NUMBER)
    ]

    def __is_bad_string_ptr_A(self, lpsz, ucchMax):
        result = FunctionResult(0, FunctionResult.NUMBER) # fake read access
        return self._wrap_results(result)

    __is_bad_write_ptr_arguments = [
        FunctionArgument('lp', FunctionArgument.ADDRESS),
        FunctionArgument('ucb', FunctionArgument.NUMBER)
    ]

    def __is_bad_write_ptr(self, lp, ucb):
        result = FunctionResult(0, FunctionResult.NUMBER) # fake write access
        return self._wrap_results(result)

    __is_native_vhd_boot_arguments = [
        FunctionArgument('nativeVhdBoot', FunctionArgument.ADDRESS)
    ]

    def __is_native_vhd_boot(self, nativeVhdBoot):
        return self._wrap_results([
            self._false_result(), # fake not VHD
            self._false_result(target=nativeVhdBoot)
        ])

    __is_system_resume_automatic_arguments = []

    def __is_system_resume_automatic(self):
        return self._wrap_results(self._false_result()) # fake user active

    __is_text_unicode_arguments = [
        FunctionArgument('lpv', FunctionArgument.ADDRESS),
        FunctionArgument('iSize', FunctionArgument.NUMBER),
        FunctionArgument('lpiResult', FunctionArgument.ADDRESS)
    ]

    def __is_text_unicode(self, lpv, iSize, lpiResult):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(1, FunctionResult.NUMBER, target=lpiResult)
        ])

    __load_module_arguments = [
        FunctionArgument('lpModuleName', FunctionArgument.STRING),
        FunctionArgument('lpParameterBlock', FunctionArgument.ADDRESS)
    ]

    def __load_module(self, lpModuleName, lpParameterBlock):
        result = FunctionResult(32, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __load_packaged_library_arguments = [
        FunctionArgument('lpwLibFileName', FunctionArgument.STRING),
        FunctionArgument('reserved', FunctionArgument.NUMBER)
    ]

    def __load_packaged_library(self, lpwLibFileName, reserved):
        return self._wrap_results(self._new_address_result())

    __local_alloc_arguments = [
        FunctionArgument('uFlags', FunctionArgument.NUMBER),
        FunctionArgument('dwBytes', FunctionArgument.NUMBER)
    ]

    def __local_alloc(self, uFlags, dwBytes):
        result = FunctionResult(dwBytes, FunctionResult.NUMBER, to_reference=True) if dwBytes > 0 else self._new_address_result()
        return self._wrap_results(result)

    __local_flags_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __local_flags(self, hMem):
        result = FunctionResult(int('0x11111111', 16), FunctionResult.NUMBER) # fake allocation values and lock count
        return self._wrap_results(result)

    __local_free_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __local_free(self, hMem):
        return self._wrap_results(self._null_result())

    __local_handle_arguments = [
        FunctionArgument('pMem', FunctionArgument.ADDRESS)
    ]

    def __local_handle(self, pMem):
        result = FunctionResult(int(pMem, 16), FunctionResult.NUMBER)
        return self._wrap_results(result)

    __local_lock_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __local_lock(self, hMem):
        result = FunctionResult(int(hMem, 16), FunctionResult.NUMBER)
        return self._wrap_results(result)

    __local_re_alloc_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS),
        FunctionArgument('dwBytes', FunctionArgument.NUMBER),
        FunctionArgument('uFlags', FunctionArgument.NUMBER)
    ]

    def __local_re_alloc(self, hMem, dwBytes, uFlags):
        result = FunctionResult(dwBytes, FunctionResult.NUMBER, to_reference=True)
        return self._wrap_results(result)

    __local_size_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __local_size(self, hMem):
        result = FunctionResult(10, FunctionResult.NUMBER) # fake 10 bytes of memory
        return self._wrap_results(result)

    __local_unlock_arguments = [
        FunctionArgument('hMem', FunctionArgument.ADDRESS)
    ]

    def __local_unlock(self, hMem):
        result = FunctionResult(0, FunctionResult.NUMBER) # memory object unlocked
        return self._wrap_results(result)

    __locate_X_state_feature_arguments = [
        FunctionArgument('context', FunctionArgument.ADDRESS),
        FunctionArgument('featureId', FunctionArgument.NUMBER),
        FunctionArgument('length', FunctionArgument.ADDRESS)
    ]

    def __locate_X_state_feature(self, context, featureId, length):
        return self._wrap_results([
            self._new_address_result(),
            FunctionResult(1024, FunctionResult.NUMBER, target=length) # fake 1KB length
        ])

    __logon_user_A_arguments = [
        FunctionArgument('lpszUsername', FunctionArgument.STRING),
        FunctionArgument('lpszDomain', FunctionArgument.STRING),
        FunctionArgument('lpszPassword', FunctionArgument.STRING),
        FunctionArgument('dwLogonType', FunctionArgument.NUMBER),
        FunctionArgument('dwLogonProvider', FunctionArgument.NUMBER),
        FunctionArgument('phToken', FunctionArgument.ADDRESS)
    ]

    def __logon_user_A(self, lpszUsername, lpszDomain, lpszPassword, dwLogonType, dwLogonProvider, phToken):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=phToken)
        ])

    __logon_user_ex_A_arguments = [
        FunctionArgument('lpszUsername', FunctionArgument.STRING),
        FunctionArgument('lpszDomain', FunctionArgument.STRING),
        FunctionArgument('lpszPassword', FunctionArgument.STRING),
        FunctionArgument('dwLogonType', FunctionArgument.NUMBER),
        FunctionArgument('dwLogonProvider', FunctionArgument.NUMBER),
        FunctionArgument('phToken', FunctionArgument.ADDRESS),
        FunctionArgument('ppLogonSid', FunctionArgument.ADDRESS),
        FunctionArgument('ppProfileBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('pdwProfileLength', FunctionArgument.ADDRESS),
        FunctionArgument('pQuotaLimits', FunctionArgument.ADDRESS)
    ]

    def __logon_user_ex_A(self, lpszUsername, lpszDomain, lpszPassword, dwLogonType, dwLogonProvider, phToken, ppLogonSid, ppProfileBuffer, pdwProfileLength, pQuotaLimits):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=phToken),
            self._new_address_result(target=ppLogonSid),
            self._new_address_result(target=ppProfileBuffer),
            FunctionResult(16, FunctionResult.NUMBER, target=pdwProfileLength) # fake 16 bytes
        ])

    __lookup_account_name_A_arguments = [
        FunctionArgument('lpSystemName', FunctionArgument.STRING),
        FunctionArgument('lpAccountName', FunctionArgument.STRING),
        FunctionArgument('sid', FunctionArgument.ADDRESS),
        FunctionArgument('cbSid', FunctionArgument.ADDRESS),
        FunctionArgument('referencedDomainName', FunctionArgument.ADDRESS),
        FunctionArgument('cchReferencedDomainName', FunctionArgument.ADDRESS),
        FunctionArgument('peUse', FunctionArgument.ADDRESS)
    ]

    def __lookup_account_name_A(self, lpSystemName, lpAccountName, sid, cbSid, referencedDomainName, cchReferencedDomainName, peUse):
        domain = b'domain\x00'
        result = [
            FunctionResult(1, FunctionResult.NUMBER)
        ]
        if not util.is_zero(sid): result.append(self._new_address_result(target=sid))
        if util.is_zero(cbSid): result.append(FunctionResult(len(domain), FunctionResult.NUMBER, target=cbSid))
        if util.is_zero(referencedDomainName): result.append(FunctionResult(len(domain), FunctionResult.NUMBER, target=referencedDomainName))
        else: result.append(FunctionResult(domain, FunctionResult.BYTES, target=referencedDomainName))
        return self._wrap_results(result)

    __lookup_account_sid_A_arguments = [
        FunctionArgument('lpSystemName', FunctionArgument.STRING),
        FunctionArgument('sid', FunctionArgument.ADDRESS),
        FunctionArgument('name', FunctionArgument.ADDRESS),
        FunctionArgument('cchName', FunctionArgument.ADDRESS),
        FunctionArgument('referencedDomainName', FunctionArgument.ADDRESS),
        FunctionArgument('cchReferencedDomainName', FunctionArgument.ADDRESS),
        FunctionArgument('peUse', FunctionArgument.ADDRESS)
    ]

    def __lookup_account_sid_A(self, lpSystemName, sid, name, cchName, referencedDomainName, cchReferencedDomainName, peUse):
        account, domain = b'account\x00', b'domain\x00'
        result = [
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(account, FunctionResult.BYTES, target=name),
            FunctionResult(domain, FunctionResult.BYTES, target=referencedDomainName)
        ]
        if util.is_zero(cchName): result.append(FunctionResult(len(account), FunctionResult.NUMBER, target=cchName))
        if util.is_zero(cchReferencedDomainName): result.append(FunctionResult(len(domain), FunctionResult.NUMBER, target=cchReferencedDomainName))
        return self._wrap_results(result)

    __lookup_account_sid_local_A_arguments = [
        FunctionArgument('sid', FunctionArgument.ADDRESS),
        FunctionArgument('name', FunctionArgument.ADDRESS),
        FunctionArgument('cchName', FunctionArgument.ADDRESS),
        FunctionArgument('referencedDomainName', FunctionArgument.ADDRESS),
        FunctionArgument('cchReferencedDomainName', FunctionArgument.ADDRESS),
        FunctionArgument('peUse', FunctionArgument.ADDRESS)
    ]

    def __lookup_account_sid_local_A(self, sid, name, cchName, referencedDomainName, cchReferencedDomainName, peUse):
        account, domain = b'account\x00', b'domain\x00'
        result = [
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(account, FunctionResult.BYTES, target=name),
            FunctionResult(domain, FunctionResult.BYTES, target=referencedDomainName)
        ]
        if util.is_zero(cchName): result.append(FunctionResult(len(account), FunctionResult.NUMBER, target=cchName))
        if util.is_zero(cchReferencedDomainName): result.append(FunctionResult(len(domain), FunctionResult.NUMBER, target=cchReferencedDomainName))
        return self._wrap_results(result)

    __lookup_privilege_display_name_A_arguments = [
        FunctionArgument('lpSystemName', FunctionArgument.STRING),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpDisplayName', FunctionArgument.ADDRESS),
        FunctionArgument('cchDisplayName', FunctionArgument.ADDRESS),
        FunctionArgument('lpLanguageId', FunctionArgument.ADDRESS)
    ]

    def __lookup_privilege_display_name_A(self, lpSystemName, lpName, lpDisplayName, cchDisplayName, lpLanguageId):
        data = b'display_name'
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpDisplayName),
            FunctionResult(len(data), FunctionResult.NUMBER, target=cchDisplayName),
            FunctionResult(1, FunctionResult.NUMBER, target=lpLanguageId)
        ])

    __lookup_privilege_name_A_arguments = [
        FunctionArgument('lpSystemName', FunctionArgument.STRING),
        FunctionArgument('lpLuid', FunctionArgument.ADDRESS),
        FunctionArgument('lpName', FunctionArgument.ADDRESS),
        FunctionArgument('cchName', FunctionArgument.ADDRESS)
    ]

    def __lookup_privilege_name_A(self, lpSystemName, lpLuid, lpName, cchName):
        data = b'privilege_name'
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpName),
            FunctionResult(len(data), FunctionResult.NUMBER, target=cchName)
        ])

    __lookup_privilege_value_A_arguments = [
        FunctionArgument('lpSystemName', FunctionArgument.STRING),
        FunctionArgument('lpName', FunctionArgument.ADDRESS),
        FunctionArgument('lpLuid', FunctionArgument.ADDRESS)
    ]

    def __lookup_privilege_value_A(self, lpSystemName, lpName, lpLuid):
        data = b'privilege_name'
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpName),
            FunctionResult(5, FunctionResult.NUMBER, target=lpLuid) # fake 5 LUID
        ])

    __lpprogress_routine_arguments = [
        FunctionArgument('totalFileSize', FunctionArgument.NUMBER),
        FunctionArgument('totalBytesTransferred', FunctionArgument.NUMBER),
        FunctionArgument('streamSize', FunctionArgument.NUMBER),
        FunctionArgument('streamBytesTransferred', FunctionArgument.NUMBER),
        FunctionArgument('dwStreamNumber', FunctionArgument.ADDRESS),
        FunctionArgument('dwCallbackReason', FunctionArgument.NUMBER),
        FunctionArgument('hSourceFile', FunctionArgument.ADDRESS),
        FunctionArgument('hDestinationFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpData', FunctionArgument.ADDRESS)
    ]

    def __lpprogress_routine(self, totalFileSize, totalBytesTransferred, streamSize, streamBytesTransferred, dwStreamNumber, dwCallbackReason, hSourceFile, hDestinationFile, lpData):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __lstrcat_A_arguments = [
        FunctionArgument('lpString1', FunctionArgument.STRING),
        FunctionArgument('lpString2', FunctionArgument.STRING)
    ]

    def __lstrcat_A(self, lpString1, lpString2):
        data = (lpString1+lpString2).encode() + b'\x00'
        result = FunctionResult(data, FunctionResult.BYTES, to_reference=True)
        return self._wrap_results(result)

    __lstrcmp_A_arguments = [
        FunctionArgument('lpString1', FunctionArgument.STRING),
        FunctionArgument('lpString2', FunctionArgument.STRING)
    ]

    def __lstrcmp_A(self, lpString1, lpString2):
        if lpString1 < lpString2: result = FunctionResult(-1, FunctionResult.NUMBER)
        elif lpString1 > lpString2: result = FunctionResult(1, FunctionResult.NUMBER)
        else: result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __lstrcmpi_A_arguments = [
        FunctionArgument('lpString1', FunctionArgument.STRING),
        FunctionArgument('lpString2', FunctionArgument.STRING)
    ]

    def __lstrcmpi_A(self, lpString1, lpString2):
        lpString1, lpString2 = lpString1.lower(), lpString2.lower()
        if lpString1 < lpString2: result = FunctionResult(-1, FunctionResult.NUMBER)
        elif lpString1 > lpString2: result = FunctionResult(1, FunctionResult.NUMBER)
        else: result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __lstrcpy_A_arguments = [
        FunctionArgument('lpString1', FunctionArgument.ADDRESS),
        FunctionArgument('lpString2', FunctionArgument.STRING)
    ]

    def __lstrcpy_A(self, lpString1, lpString2):
        data = lpString2.encode()+b'\x00'
        return self._wrap_results([
            FunctionResult(int(lpString1, 16), FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpString1)
        ])

    __lstrcpyn_A_arguments = [
        FunctionArgument('lpString1', FunctionArgument.ADDRESS),
        FunctionArgument('lpString2', FunctionArgument.STRING),
        FunctionArgument('lpStriiMaxLengthng2', FunctionArgument.NUMBER)
    ]

    def __lstrcpyn_A(self, lpString1, lpString2, lpStriiMaxLengthng2):
        data = lpString2.encode()[:lpStriiMaxLengthng2-1]+b'\x00'
        return self._wrap_results([
            FunctionResult(int(lpString1, 16), FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpString1)
        ])

    __lstrlen_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __lstrlen_A(self, lpString):
        result = FunctionResult(len(lpString.encode()) if lpString else 0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __map_user_physical_pages_scatter_arguments = [
        FunctionArgument('virtualAddresses', FunctionArgument.ADDRESS),
        FunctionArgument('numberOfPages', FunctionArgument.NUMBER),
        FunctionArgument('pageArray', FunctionArgument.ADDRESS)
    ]

    def __map_user_physical_pages_scatter(self, virtualAddresses, numberOfPages, pageArray):
        return self._wrap_results(self._true_result())

    __map_view_of_file_ex_numa_arguments = [
        FunctionArgument('hFileMappingObject', FunctionArgument.ADDRESS),
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('dwFileOffsetHigh', FunctionArgument.NUMBER),
        FunctionArgument('dwFileOffsetLow', FunctionArgument.NUMBER),
        FunctionArgument('dwNumberOfBytesToMap', FunctionArgument.NUMBER),
        FunctionArgument('lpBaseAddress', FunctionArgument.ADDRESS),
        FunctionArgument('nndPreferred', FunctionArgument.NUMBER)
    ]

    def __map_view_of_file_ex_numa(self, hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress, nndPreferred):
        offset = dwFileOffsetHigh*(2**8) + dwFileOffsetLow
        address = offset + int(lpBaseAddress, 16)
        result = FunctionResult(address, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __move_file_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING)
    ]

    def __move_file(self, lpExistingFileName, lpNewFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __move_file_ex_A_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __move_file_ex_A(self, lpExistingFileName, lpNewFileName, dwFlags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __move_file_transacted_A_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING),
        FunctionArgument('lpProgressRoutine', FunctionArgument.ADDRESS),
        FunctionArgument('lpData', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __move_file_transacted_A(self, lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __move_file_with_progress_A_arguments = [
        FunctionArgument('lpExistingFileName', FunctionArgument.STRING),
        FunctionArgument('lpNewFileName', FunctionArgument.STRING),
        FunctionArgument('lpProgressRoutine', FunctionArgument.ADDRESS),
        FunctionArgument('lpData', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
    ]

    def __move_file_with_progress_A(self, lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, dwFlags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __mul_div_arguments = [
        FunctionArgument('nNumber', FunctionArgument.NUMBER),
        FunctionArgument('nNumerator', FunctionArgument.NUMBER),
        FunctionArgument('nDenominator', FunctionArgument.NUMBER)
    ]

    def __mul_div(self, nNumber, nNumerator, nDenominator):
        result = round(nNumber*nNumerator/nDenominator) if nDenominator else -1
        result = FunctionResult(result, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __notify_change_event_log_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('hEvent', FunctionArgument.ADDRESS)
    ]

    def __notify_change_event_log(self, hEventLog, hEvent):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __object_close_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.NUMBER),
        FunctionArgument('generateOnClose', FunctionArgument.NUMBER)
    ]

    def __object_close_audit_alarm_A(self, subsystemName, handleId, generateOnClose):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __object_delete_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.NUMBER),
        FunctionArgument('generateOnClose', FunctionArgument.NUMBER)
    ]

    def __object_delete_audit_alarm_A(self, subsystemName, handleId, generateOnClose):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __object_open_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.NUMBER),
        FunctionArgument('objectTypeName', FunctionArgument.STRING),
        FunctionArgument('objectName', FunctionArgument.STRING),
        FunctionArgument('pSecurityDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('clientToken', FunctionArgument.ADDRESS),
        FunctionArgument('desiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('grantedAccess', FunctionArgument.NUMBER),
        FunctionArgument('privileges', FunctionArgument.ADDRESS),
        FunctionArgument('objectCreation', FunctionArgument.NUMBER),
        FunctionArgument('accessGranted', FunctionArgument.NUMBER),
        FunctionArgument('generateOnClose', FunctionArgument.NUMBER)
    ]

    def __object_open_audit_alarm_A(self, subsystemName, handleId, objectTypeName, objectName, pSecurityDescriptor, clientToken, desiredAccess, grantedAccess, privileges, objectCreation, accessGranted, generateOnClose):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __object_privilege_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('handleId', FunctionArgument.NUMBER),
        FunctionArgument('clientToken', FunctionArgument.ADDRESS),
        FunctionArgument('desiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('privileges', FunctionArgument.ADDRESS),
        FunctionArgument('accessGranted', FunctionArgument.NUMBER),
    ]

    def __object_privilege_audit_alarm_A(self, subsystemName, handleId, clientToken, desiredAccess, privileges, accessGranted):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __open_backup_event_log_A_arguments = [
        FunctionArgument('lpUNCServerName', FunctionArgument.STRING),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __open_backup_event_log_A(self, lpUNCServerName, lpFileName):
        return self._wrap_results(self._new_address_result())

    __open_comm_port_arguments = [
        FunctionArgument('uPortNumber', FunctionArgument.NUMBER),
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('dwFlagsAndAttributes', FunctionArgument.NUMBER)
    ]

    def __open_comm_port(self, uPortNumber, dwDesiredAccess, dwFlagsAndAttributes):
        return self._wrap_results(self._new_address_result())

    __open_encrypted_file_raw_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('ulFlags', FunctionArgument.NUMBER),
        FunctionArgument('pvContext', FunctionArgument.ADDRESS)
    ]

    def __open_encrypted_file_raw_A(self, lpFileName, ulFlags, pvContext):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __open_event_log_A_arguments = [
        FunctionArgument('lpUNCServerName', FunctionArgument.STRING),
        FunctionArgument('lpSourceName', FunctionArgument.STRING)
    ]

    def __open_event_log_A(self, lpUNCServerName, lpSourceName):
        return self._wrap_results(self._new_address_result())

    __open_file_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('lpReOpenBuff', FunctionArgument.ADDRESS),
        FunctionArgument('uStyle', FunctionArgument.NUMBER)
    ]

    def __open_file(self, lpFileName, lpReOpenBuff, uStyle):
        return self._wrap_results(self._new_address_result())

    __open_file_by_id_arguments = [
        FunctionArgument('hVolumeHint', FunctionArgument.ADDRESS),
        FunctionArgument('lpFileId', FunctionArgument.ADDRESS),
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('dwShareMode', FunctionArgument.NUMBER),
        FunctionArgument('lpSecurityAttributes', FunctionArgument.NUMBER),
        FunctionArgument('dwFlagsAndAttributes', FunctionArgument.NUMBER)
    ]

    def __open_file_by_id(self, hVolumeHint, lpFileId, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwFlagsAndAttributes):
        return self._wrap_results(self._new_address_result())

    __open_file_mapping_A_arguments = [
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('bInheritHandle', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING)
    ]

    def __open_file_mapping_A(self, dwDesiredAccess, bInheritHandle, lpName):
        return self._wrap_results(self._new_address_result())

    __open_job_object_A_arguments = [
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('bInheritHandle', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING)
    ]

    def __open_job_object_A(self, dwDesiredAccess, bInheritHandle, lpName):
        return self._wrap_results(self._new_address_result())

    __open_private_namespace_A_arguments = [
        FunctionArgument('lpBoundaryDescriptor', FunctionArgument.ADDRESS),
        FunctionArgument('lpAliasPrefix', FunctionArgument.STRING)
    ]

    def __open_private_namespace_A(self, lpBoundaryDescriptor, lpAliasPrefix):
        return self._wrap_results(self._new_address_result())

    __operation_end_arguments = [
        FunctionArgument('operationEndParams', FunctionArgument.ADDRESS)
    ]

    def __operation_end(self, operationEndParams):
        return self._wrap_results(self._true_result())

    __operation_start_arguments = [
        FunctionArgument('operationStartParams', FunctionArgument.ADDRESS)
    ]

    def __operation_start(self, operationStartParams):
        return self._wrap_results(self._true_result())

    __pcopyfile2_progress_routine_arguments = [
        FunctionArgument('pMessage', FunctionArgument.ADDRESS),
        FunctionArgument('pvCallbackContext', FunctionArgument.ADDRESS)
    ]

    def __pcopyfile2_progress_routine(self, pMessage, pvCallbackContext):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __pfe_export_func_arguments = [
        FunctionArgument('pbData', FunctionArgument.ADDRESS),
        FunctionArgument('pvCallbackContext', FunctionArgument.ADDRESS),
        FunctionArgument('ulLength', FunctionArgument.NUMBER)
    ]

    def __pfe_export_func(self, pbData, pvCallbackContext, ulLength):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __pfe_import_func_arguments = [
        FunctionArgument('pbData', FunctionArgument.ADDRESS),
        FunctionArgument('pvCallbackContext', FunctionArgument.ADDRESS),
        FunctionArgument('ulLength', FunctionArgument.NUMBER)
    ]

    def __pfe_import_func(self, pbData, pvCallbackContext, ulLength):
        data = b'some fake data'[:ulLength]
        return self._wrap_results([
            FunctionResult(0, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=pbData)
        ])

    __pfiber_start_routine_arguments = [
        FunctionArgument('lpFiberParameter', FunctionArgument.ADDRESS)
    ]

    def __pfiber_start_routine(self, lpFiberParameter):
        return self._wrap_results(None)

    __power_clear_request_arguments = [
        FunctionArgument('powerRequest', FunctionArgument.ADDRESS),
        FunctionArgument('requestType', FunctionArgument.NUMBER)
    ]

    def __power_clear_request(self, powerRequest, requestType):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __power_create_request_arguments = [
        FunctionArgument('context', FunctionArgument.ADDRESS)
    ]

    def __power_create_request(self, context):
        return self._wrap_results(self._new_address_result())

    __power_set_request_arguments = [
        FunctionArgument('powerRequest', FunctionArgument.ADDRESS),
        FunctionArgument('requestType', FunctionArgument.NUMBER)
    ]

    def __power_set_request(self, powerRequest, requestType):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __prepare_tape_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwOperation', FunctionArgument.NUMBER),
        FunctionArgument('bImmediate', FunctionArgument.NUMBER)
    ]

    def __prepare_tape(self, hDevice, dwOperation, bImmediate):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __privileged_service_audit_alarm_A_arguments = [
        FunctionArgument('subsystemName', FunctionArgument.STRING),
        FunctionArgument('serviceName', FunctionArgument.STRING),
        FunctionArgument('clientToken', FunctionArgument.ADDRESS),
        FunctionArgument('privileges', FunctionArgument.ADDRESS),
        FunctionArgument('accessGranted', FunctionArgument.NUMBER)
    ]

    def __privileged_service_audit_alarm_A(self, subsystemName, serviceName, clientToken, privileges, accessGranted):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __pulse_event_arguments = [
        FunctionArgument('hEvent', FunctionArgument.ADDRESS)
    ]

    def __pulse_event(self, hEvent):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __purge_comm_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __purge_comm(self, hFile, dwFlags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __query_act_ctx_settings_W_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('hActCtx', FunctionArgument.ADDRESS),
        FunctionArgument('settingsNameSpace', FunctionArgument.STRING),
        FunctionArgument('settingName', FunctionArgument.STRING),
        FunctionArgument('pvBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('dwBuffer', FunctionArgument.NUMBER),
        FunctionArgument('pdwWrittenOrRequired', FunctionArgument.ADDRESS)
    ]

    def __query_act_ctx_settings_W(self, dwFlags, hActCtx, settingsNameSpace, settingName, pvBuffer, dwBuffer, pdwWrittenOrRequired):
        data = b'context_query_results\x00'
        return self._wrap_results([
            self._true_result(),
            FunctionResult(data[:dwBuffer], FunctionResult.BYTES, target=pvBuffer),
            FunctionResult(len(data), FunctionResult.NUMBER, target=pdwWrittenOrRequired)
        ])

    __query_act_ctx_W_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('hActCtx', FunctionArgument.ADDRESS),
        FunctionArgument('pvSubInstance', FunctionArgument.NUMBER),
        FunctionArgument('ulInfoClass', FunctionArgument.NUMBER),
        FunctionArgument('pvBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('cbBuffer', FunctionArgument.NUMBER),
        FunctionArgument('pcbWrittenOrRequired', FunctionArgument.ADDRESS)
    ]

    def __query_act_ctx_W(self, dwFlags, hActCtx, pvSubInstance, ulInfoClass, pvBuffer, cbBuffer, pcbWrittenOrRequired):
        data = b'fake_context_information'
        result = [
            self._true_result()
        ]
        if not util.is_zero(pvBuffer):
            result.append(FunctionResult(data[:cbBuffer-1]+b'\x00', FunctionResult.BYTES, target=pvBuffer))
            result.append(FunctionResult(len(data)+1, FunctionResult.NUMBER, target=pcbWrittenOrRequired))
        return self._wrap_results(result)

    __query_dos_device_A_arguments = [
        FunctionArgument('lpDeviceName', FunctionArgument.STRING),
        FunctionArgument('lpTargetPath', FunctionArgument.ADDRESS),
        FunctionArgument('ucchMax', FunctionArgument.NUMBER)
    ]

    def __query_dos_device_A(self, lpDeviceName, lpTargetPath, ucchMax):
        data = b'devicename1\x00devicename2'[:ucchMax-2] + b'\x00\x00' # fake device names
        return self._wrap_results([
            FunctionResult(len(data), FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpTargetPath)
        ])

    __query_full_process_image_name_A_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpExeName', FunctionArgument.ADDRESS),
        FunctionArgument('lpdwSize', FunctionArgument.ADDRESS)
    ]

    def __query_full_process_image_name_A(self, hProcess, dwFlags, lpExeName, lpdwSize):
        data = b'C:\\path\\to\\image' # fake image full path
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data+b'\x00', FunctionResult.BYTES, target=lpExeName),
            FunctionResult(len(data), FunctionResult.NUMBER, target=lpdwSize)
        ])

    __query_thread_profiling_arguments = [
        FunctionArgument('threadHandle', FunctionArgument.ADDRESS),
        FunctionArgument('enabled', FunctionArgument.ADDRESS)
    ]

    def __query_thread_profiling(self, threadHandle, enabled):
        return self._wrap_results([
            FunctionResult(0, FunctionResult.NUMBER),
            self._true_result(target=enabled)
        ])

    __query_ums_thread_information_arguments = [
        FunctionArgument('umsThread', FunctionArgument.ADDRESS),
        FunctionArgument('umsThreadInfoClass', FunctionArgument.NUMBER),
        FunctionArgument('umsThreadInformation', FunctionArgument.ADDRESS),
        FunctionArgument('umsThreadInformationLength', FunctionArgument.NUMBER),
        FunctionArgument('returnLength', FunctionArgument.ADDRESS)
    ]

    def __query_ums_thread_information(self, umsThread, umsThreadInfoClass, umsThreadInformation, umsThreadInformationLength, returnLength):
        data = b'some_thread_information\x00'[:umsThreadInformationLength] # fake thread information
        return self._wrap_results([
            FunctionResult(1, FunctionArgument.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=umsThreadInformation),
            FunctionResult(len(data), FunctionResult.NUMBER, target=returnLength)
        ])

    __read_directory_changes_ex_W_arguments = [
        FunctionArgument('hDirectory', FunctionArgument.ADDRESS),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('bWatchSubtree', FunctionArgument.NUMBER),
        FunctionArgument('dwNotifyFilter', FunctionArgument.NUMBER),
        FunctionArgument('lpBytesReturned', FunctionArgument.ADDRESS),
        FunctionArgument('lpOverlapped', FunctionArgument.ADDRESS),
        FunctionArgument('lpCompletionRoutine', FunctionArgument.ADDRESS),
        FunctionArgument('readDirectoryNotifyInformationClass', FunctionArgument.NUMBER)
    ]

    def __read_directory_changes_ex_W(self, hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, readDirectoryNotifyInformationClass):
        data = b'some directory changes made\x00'[:nBufferLength] # fake data
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpBuffer),
            FunctionResult(len(data), FunctionResult.NUMBER, target=lpBytesReturned)
        ])

    __ReadDirectoryChangesW_arguments = [
        FunctionArgument('hDirectory', FunctionArgument.ADDRESS),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nBufferLength', FunctionArgument.NUMBER),
        FunctionArgument('bWatchSubtree', FunctionArgument.NUMBER),
        FunctionArgument('dwNotifyFilter', FunctionArgument.NUMBER),
        FunctionArgument('lpBytesReturned', FunctionArgument.ADDRESS),
        FunctionArgument('lpOverlapped', FunctionArgument.ADDRESS),
        FunctionArgument('lpCompletionRoutine', FunctionArgument.ADDRESS),
    ]

    def __read_directory_changes_W(self, hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine):
        data = b'some directory changes made\x00'[:nBufferLength] # fake data
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data, FunctionResult.BYTES, target=lpBuffer),
            FunctionResult(len(data), FunctionResult.NUMBER, target=lpBytesReturned)
        ])

    __read_encrypted_file_raw_arguments = [
        FunctionArgument('pfExportCallback', FunctionArgument.ADDRESS),
        FunctionArgument('pvCallbackContext', FunctionArgument.ADDRESS),
        FunctionArgument('pvContext', FunctionArgument.ADDRESS)
    ]

    def __read_encrypted_file_raw(self, pfExportCallback, pvCallbackContext, pvContext):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __read_event_log_A_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('dwReadFlags', FunctionArgument.NUMBER),
        FunctionArgument('dwRecordOffset', FunctionArgument.NUMBER),
        FunctionArgument('lpBuffer', FunctionArgument.ADDRESS),
        FunctionArgument('nNumberOfBytesToRead', FunctionArgument.NUMBER),
        FunctionArgument('pnBytesRead', FunctionArgument.ADDRESS),
        FunctionArgument('pnMinNumberOfBytesNeeded', FunctionArgument.ADDRESS)
    ]

    def __read_event_log_A(self, hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, pnBytesRead, pnMinNumberOfBytesNeeded):
        data = b'some_event_log_data\x00' # fake event log data; should be EVENTLOGRECORD structures
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(data[:nNumberOfBytesToRead], FunctionResult.BYTES, target=lpBuffer),
            FunctionResult(min(len(data), nNumberOfBytesToRead), FunctionResult.NUMBER, target=pnBytesRead),
            FunctionResult(len(data), FunctionResult.NUMBER, target=pnMinNumberOfBytesNeeded)
        ])

    __read_thread_profiling_data_arguments = [
        FunctionArgument('performanceDataHandle', FunctionArgument.ADDRESS),
        FunctionArgument('flags', FunctionArgument.NUMBER),
        FunctionArgument('performanceData', FunctionArgument.ADDRESS)
    ]

    def __read_thread_profiling_data(self, performanceDataHandle, flags, performanceData):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __register_application_recovery_callback_arguments = [
        FunctionArgument('pRecoveyCallback', FunctionArgument.ADDRESS),
        FunctionArgument('pvParameter', FunctionArgument.ADDRESS),
        FunctionArgument('dwPingInterval', FunctionArgument.NUMBER),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __register_application_recovery_callback(self, pRecoveyCallback, pvParameter, dwPingInterval, dwFlags):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __register_application_restart_arguments = [
        FunctionArgument('pwzCommandline', FunctionArgument.STRING),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __register_application_restart(self, pwzCommandline, dwFlags):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __register_event_source_A_arguments = [
        FunctionArgument('lpUNCServerName', FunctionArgument.STRING),
        FunctionArgument('lpSourceName', FunctionArgument.STRING)
    ]

    def __register_event_source_A(self, lpUNCServerName, lpSourceName):
        return self._wrap_results(self._new_address_result())

    __register_wait_for_single_object_arguments = [
        FunctionArgument('phNewWaitObject', FunctionArgument.ADDRESS),
        FunctionArgument('hObject', FunctionArgument.ADDRESS),
        FunctionArgument('callback', FunctionArgument.ADDRESS),
        FunctionArgument('context', FunctionArgument.ADDRESS),
        FunctionArgument('dwMilliseconds', FunctionArgument.NUMBER),
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __register_wait_for_single_object(self, phNewWaitObject, hObject, callback, context, dwMilliseconds, dwFlags):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=phNewWaitObject)
        ])

    __release_act_ctx_arguments = [
        FunctionArgument('hActCtx', FunctionArgument.ADDRESS)
    ]

    def __release_act_ctx(self, hActCtx):
        return self._wrap_results(None)

    __remove_directory_transacted_A_arguments = [
        FunctionArgument('lpPathName', FunctionArgument.STRING),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __remove_directory_transacted_A(self, lpPathName, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __remove_secure_memory_cache_callback_arguments = [
        FunctionArgument('pfnCallBack', FunctionArgument.ADDRESS)
    ]

    def __remove_secure_memory_cache_callback(self, pfnCallBack):
        return self._wrap_results(self._true_result())

    __re_open_file_arguments = [
        FunctionArgument('hOriginalFile', FunctionArgument.ADDRESS),
        FunctionArgument('dwDesiredAccess', FunctionArgument.NUMBER),
        FunctionArgument('dwShareMode', FunctionArgument.NUMBER),
        FunctionArgument('dwFlagsAndAttributes', FunctionArgument.NUMBER)
    ]

    def __re_open_file(self, hOriginalFile, dwDesiredAccess, dwShareMode, dwFlagsAndAttributes):
        return self._wrap_results(self._new_address_result())

    __replace_file_A_arguments = [
        FunctionArgument('lpReplacedFileName', FunctionArgument.STRING),
        FunctionArgument('lpReplacementFileName', FunctionArgument.STRING),
        FunctionArgument('lpBackupFileName', FunctionArgument.STRING),
        FunctionArgument('dwReplaceFlags', FunctionArgument.NUMBER),
        FunctionArgument('lpExclude', FunctionArgument.ADDRESS),
        FunctionArgument('lpReserved', FunctionArgument.ADDRESS)
    ]

    def __replace_file_A(self, lpReplacedFileName, lpReplacementFileName, lpBackupFileName, dwReplaceFlags, lpExclude, lpReserved):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __report_event_A_arguments = [
        FunctionArgument('hEventLog', FunctionArgument.ADDRESS),
        FunctionArgument('wType', FunctionArgument.NUMBER),
        FunctionArgument('wCategory', FunctionArgument.NUMBER),
        FunctionArgument('dwEventID', FunctionArgument.NUMBER),
        FunctionArgument('lpUserSid', FunctionArgument.ADDRESS),
        FunctionArgument('wNumStrings', FunctionArgument.NUMBER),
        FunctionArgument('dwDataSize', FunctionArgument.NUMBER),
        FunctionArgument('lpStrings', FunctionArgument.ADDRESS),
        FunctionArgument('lpRawData', FunctionArgument.ADDRESS)
    ]

    def __report_event_A(self, hEventLog, wType, wCategory, dwEventID, lpUserSid, wNumStrings, dwDataSize, lpStrings, lpRawData):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __request_wakeup_latency_arguments = [
        FunctionArgument('latency', FunctionArgument.NUMBER)
    ]

    def __request_wakeup_latency(self, latency):
        result = FunctionResult(10, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_comm_break_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS)
    ]

    def __set_comm_break(self, hFile):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_comm_config_arguments = [
        FunctionArgument('hCommDev', FunctionArgument.ADDRESS),
        FunctionArgument('lpCC', FunctionArgument.ADDRESS),
        FunctionArgument('dwSize', FunctionArgument.NUMBER)
    ]

    def __set_comm_config(self, hCommDev, lpCC, dwSize):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_comm_mask_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('dwEvtMask', FunctionArgument.NUMBER)
    ]

    def __set_comm_mask(self, hFile, dwEvtMask):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_comm_state_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpDCB', FunctionArgument.ADDRESS)
    ]

    def __set_comm_state(self, hFile, lpDCB):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_comm_timeouts_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpCommTimeouts', FunctionArgument.ADDRESS)
    ]

    def __set_comm_timeouts(self, hFile, lpCommTimeouts):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_current_directory_arguments = [
        FunctionArgument('lpPathName', FunctionArgument.STRING)
    ]

    def __set_current_directory(self, lpPathName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_default_comm_config_A_arguments = [
        FunctionArgument('lpszName', FunctionArgument.STRING),
        FunctionArgument('lpCC', FunctionArgument.ADDRESS),
        FunctionArgument('dwSize', FunctionArgument.NUMBER)
    ]

    def __set_default_comm_config_A(self, lpszName, lpCC, dwSize):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_dll_directory_A_arguments = [
        FunctionArgument('lpPathName', FunctionArgument.STRING)
    ]

    def __set_dll_directory_A(self, lpPathName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_environment_variable_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpValue', FunctionArgument.STRING)
    ]

    def __set_environment_variable(self, lpName, lpValue):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_file_attributes_transacted_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('dwFileAttributes', FunctionArgument.NUMBER),
        FunctionArgument('hTransaction', FunctionArgument.ADDRESS)
    ]

    def __set_file_attributes_transacted_A(self, lpFileName, dwFileAttributes, hTransaction):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_file_bandwidth_reservation_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('nPeriodMilliseconds', FunctionArgument.NUMBER),
        FunctionArgument('nBytesPerPeriod', FunctionArgument.NUMBER),
        FunctionArgument('bDiscardable', FunctionArgument.NUMBER),
        FunctionArgument('lpTransferSize', FunctionArgument.ADDRESS),
        FunctionArgument('lpNumOutstandingRequests', FunctionArgument.ADDRESS)
    ]

    def __set_file_bandwidth_reservation(self, hFile, nPeriodMilliseconds, nBytesPerPeriod, bDiscardable, lpTransferSize, lpNumOutstandingRequests):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            FunctionResult(576, FunctionResult.NUMBER, target=lpTransferSize),
            FunctionResult(100, FunctionResult.NUMBER, target=lpNumOutstandingRequests)
        ])

    __set_file_completion_notification_modes_arguments = [
        FunctionArgument('fileHandle', FunctionArgument.ADDRESS),
        FunctionArgument('flags', FunctionArgument.NUMBER)
    ]

    def __set_file_completion_notification_modes(self, fileHandle, flags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_file_security_A_arguments = [
        FunctionArgument('lpFileName', FunctionArgument.STRING),
        FunctionArgument('securityInformation', FunctionArgument.ADDRESS),
        FunctionArgument('pSecurityDescriptor', FunctionArgument.ADDRESS)
    ]

    def __set_file_security_A(self, lpFileName, securityInformation, pSecurityDescriptor):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_file_short_name_A_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpShortName', FunctionArgument.STRING)
    ]

    def __set_file_short_name_A(self, hFile, lpShortName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_firmware_environment_variable_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpGuid', FunctionArgument.STRING),
        FunctionArgument('pValue', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER)
    ]

    def __set_firmware_environment_variable_A(self, lpName, lpGuid, pValue, nSize):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_firmware_environment_variable_ex_A_arguments = [
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('lpGuid', FunctionArgument.STRING),
        FunctionArgument('pValue', FunctionArgument.ADDRESS),
        FunctionArgument('nSize', FunctionArgument.NUMBER),
        FunctionArgument('dwAttributes', FunctionArgument.NUMBER)
    ]

    def __set_firmware_environment_variable_ex_A(self, lpName, lpGuid, pValue, nSize, dwAttributes):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_handle_count_arguments = [
        FunctionArgument('uNumber', FunctionArgument.NUMBER)
    ]

    def __set_handle_count(self, uNumber):
        result = FunctionResult(uNumber, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_mailslot_info_arguments = [
        FunctionArgument('hMailslot', FunctionArgument.ADDRESS),
        FunctionArgument('lReadTimeout', FunctionArgument.NUMBER)
    ]

    def __set_mailslot_info(self, hMailslot, lReadTimeout):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_process_affinity_mask_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('dwProcessAffinityMask', FunctionArgument.NUMBER)
    ]

    def __set_process_affinity_mask(self, hProcess, dwProcessAffinityMask):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_process_DEP_policy_arguments = [
        FunctionArgument('dwFlags', FunctionArgument.NUMBER)
    ]

    def __set_process_DEP_policy(self, dwFlags):
        return self._wrap_results(self._true_result())

    __set_process_working_set_size_arguments = [
        FunctionArgument('hProcess', FunctionArgument.ADDRESS),
        FunctionArgument('dwMinimumWorkingSetSize', FunctionArgument.NUMBER),
        FunctionArgument('dwMaximumWorkingSetSize', FunctionArgument.NUMBER)
    ]

    def __set_process_working_set_size(self, hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_search_path_mode_arguments = [
        FunctionArgument('flags', FunctionArgument.NUMBER)
    ]

    def __set_search_path_mode(self, flags):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_system_power_state_arguments = [
        FunctionArgument('fSuspend', FunctionArgument.NUMBER),
        FunctionArgument('fForce', FunctionArgument.NUMBER)
    ]

    def __set_system_power_state(self, fSuspend, fForce):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_tape_parameters_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwOperation', FunctionArgument.NUMBER),
        FunctionArgument('lpTapeInformation', FunctionArgument.ADDRESS)
    ]

    def __set_tape_parameters(self, hDevice, dwOperation, lpTapeInformation):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_tape_position_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwPositionMethod', FunctionArgument.NUMBER),
        FunctionArgument('dwPartition', FunctionArgument.NUMBER),
        FunctionArgument('dwOffsetLow', FunctionArgument.NUMBER),
        FunctionArgument('dwOffsetHigh', FunctionArgument.NUMBER),
        FunctionArgument('bImmediate', FunctionArgument.NUMBER)
    ]

    def __set_tape_position(self, hDevice, dwPositionMethod, dwPartition, dwOffsetLow, dwOffsetHigh, bImmediate):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_thread_affinity_mask_arguments = [
        FunctionArgument('hThread', FunctionArgument.ADDRESS),
        FunctionArgument('dwThreadAffinityMask', FunctionArgument.NUMBER)
    ]

    def __set_thread_affinity_mask(self, hThread, dwThreadAffinityMask):
        result = FunctionResult(int('0x11111111', 16), FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_thread_execution_state_arguments = [
        FunctionArgument('esFlags', FunctionArgument.NUMBER)
    ]

    def __set_thread_execution_state(self, esFlags):
        result = FunctionResult(int('0x80000000', 16), FunctionResult.NUMBER) # fake ES_CONTINUOUS state
        return self._wrap_results(result)

    __set_threadpool_callback_cleanup_group_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS),
        FunctionArgument('ptpcg', FunctionArgument.ADDRESS),
        FunctionArgument('pfng', FunctionArgument.ADDRESS)
    ]

    def __set_threadpool_callback_cleanup_group(self, pcbe, ptpcg, pfng):
        return self._wrap_results(None)

    __set_threadpool_callback_library_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS),
        FunctionArgument('mod', FunctionArgument.ADDRESS)
    ]

    def __set_threadpool_callback_library(self, pcbe, mod):
        return self._wrap_results(None)

    __set_threadpool_callback_persistent_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS)
    ]

    def __set_threadpool_callback_persistent(self, pcbe):
        return self._wrap_results(None)

    __set_threadpool_callback_pool_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS),
        FunctionArgument('ptpp', FunctionArgument.ADDRESS)
    ]

    def __set_threadpool_callback_pool(self, pcbe, ptpp):
        return self._wrap_results(None)

    __set_threadpool_callback_priority_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS),
        FunctionArgument('priority', FunctionArgument.NUMBER)
    ]

    def __set_threadpool_callback_priority(self, pcbe, priority):
        return self._wrap_results(None)

    __set_threadpool_callback_runs_long_arguments = [
        FunctionArgument('pcbe', FunctionArgument.ADDRESS)
    ]

    def __set_threadpool_callback_runs_long(self, pcbe):
        return self._wrap_results(None)

    __set_ums_thread_information_arguments = [
        FunctionArgument('umsThread', FunctionArgument.ADDRESS),
        FunctionArgument('umsThreadInfoClass', FunctionArgument.NUMBER),
        FunctionArgument('umsThreadInformation', FunctionArgument.ADDRESS),
        FunctionArgument('umsThreadInformationLength', FunctionArgument.NUMBER)
    ]

    def __set_ums_thread_information(self, umsThread, umsThreadInfoClass, umsThreadInformation, umsThreadInformationLength):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __setup_comm_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('dwInQueue', FunctionArgument.NUMBER),
        FunctionArgument('dwOutQueue', FunctionArgument.NUMBER)
    ]

    def __setup_comm(self, hFile, dwInQueue, dwOutQueue):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_volume_label_A_arguments = [
        FunctionArgument('lpRootPathName', FunctionArgument.STRING),
        FunctionArgument('lpVolumeName', FunctionArgument.STRING)
    ]

    def __set_volume_label_A(self, lpRootPathName, lpVolumeName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_volume_mount_point_A_arguments = [
        FunctionArgument('lpszVolumeMountPoint', FunctionArgument.STRING),
        FunctionArgument('lpszVolumeName', FunctionArgument.STRING)
    ]

    def __set_volume_mount_point_A(self, lpszVolumeMountPoint, lpszVolumeName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __set_X_state_features_mask_arguments = [
        FunctionArgument('context', FunctionArgument.ADDRESS),
        FunctionArgument('featureMask', FunctionArgument.NUMBER)
    ]

    def __set_X_state_features_mask(self, context, featureMask):
        return self._wrap_results(self._true_result())

    __switch_to_fiber_arguments = [
        FunctionArgument('lpFiber', FunctionArgument.ADDRESS)
    ]

    def __switch_to_fiber(self, lpFiber):
        return self._wrap_results(None)

    __transmit_comm_char_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('cChar', FunctionArgument.NUMBER)
    ]

    def __transmit_comm_char(self, hFile, cChar):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __ums_thread_yield_arguments = [
        FunctionArgument('schedulerParam', FunctionArgument.ADDRESS)
    ]

    def __ums_thread_yield(self, schedulerParam):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __unregister_application_recovery_callback_arguments = []

    def __unregister_application_recovery_callback(self):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __unregister_application_restart_arguments = []

    def __unregister_application_restart(self):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __unregister_wait_arguments = [
        FunctionArgument('waitHandle', FunctionArgument.ADDRESS)
    ]

    def __unregister_wait(self, waitHandle):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __update_resource_A_arguments = [
        FunctionArgument('hUpdate', FunctionArgument.ADDRESS),
        FunctionArgument('lpType', FunctionArgument.NUMBER),
        FunctionArgument('lpName', FunctionArgument.STRING),
        FunctionArgument('wLanguage', FunctionArgument.NUMBER),
        FunctionArgument('lpData', FunctionArgument.ADDRESS),
        FunctionArgument('cb', FunctionArgument.NUMBER)
    ]

    def __update_resource_A(self, hUpdate, lpType, lpName, wLanguage, lpData, cb):
        return self._wrap_results(self._true_result())

    __verify_version_info_A_arguments = [
        FunctionArgument('lpVersionInformation', FunctionArgument.ADDRESS),
        FunctionArgument('dwTypeMask', FunctionArgument.NUMBER),
        FunctionArgument('dwlConditionMask', FunctionArgument.NUMBER)
    ]

    def __verify_version_info_A(self, lpVersionInformation, dwTypeMask, dwlConditionMask):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __wait_comm_event_arguments = [
        FunctionArgument('hFile', FunctionArgument.ADDRESS),
        FunctionArgument('lpEvtMask', FunctionArgument.ADDRESS),
        FunctionArgument('lpOverlapped', FunctionArgument.ADDRESS)
    ]

    def __wait_comm_event(self, hFile, lpEvtMask, lpOverlapped):
        return self._wrap_results([
            FunctionResult(1, FunctionArgument.NUMBER),
            FunctionResult(int('0x0004', 16), FunctionResult.NUMBER, target=lpOverlapped) # fake last character sent
        ])

    __wait_named_pipe_A_arguments = [
        FunctionArgument('lpNamedPipeName', FunctionArgument.STRING),
        FunctionArgument('nTimeOut', FunctionArgument.NUMBER)
    ]

    def __wait_named_pipe_A(self, lpNamedPipeName, nTimeOut):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __win_exec_arguments = [
        FunctionArgument('lpCmdLine', FunctionArgument.STRING),
        FunctionArgument('uCmdShow', FunctionArgument.NUMBER)
    ]

    def __win_exec(self, lpCmdLine, uCmdShow):
        result = FunctionResult(32, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __win_main_arguments = [
        FunctionArgument('hInstance', FunctionArgument.ADDRESS),
        FunctionArgument('hPrevInstance', FunctionArgument.ADDRESS),
        FunctionArgument('lpCmdLine', FunctionArgument.STRING),
        FunctionArgument('nShowCmd', FunctionArgument.NUMBER)
    ]

    def __win_main(self, hInstance, hPrevInstance, lpCmdLine, nShowCmd):
        result = FunctionResult(int('0x0012', 16), FunctionResult.NUMBER)
        return self._wrap_results(result)

    __wow64_enable_wow64_fs_redirection_arguments = [
        FunctionArgument('wow64FsEnableRedirection', FunctionArgument.NUMBER)
    ]

    def __wow64_enable_wow64_fs_redirection(self, wow64FsEnableRedirection):
        return self._wrap_results(self._true_result())

    __wow64_get_thread_context_arguments = [
        FunctionArgument('hThread', FunctionArgument.ADDRESS),
        FunctionArgument('lpContext', FunctionArgument.ADDRESS)
    ]

    def __wow64_get_thread_context(self, hThread, lpContext):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __wow64_get_thread_selector_entry_arguments = [
        FunctionArgument('hThread', FunctionArgument.ADDRESS),
        FunctionArgument('dwSelector', FunctionArgument.NUMBER),
        FunctionArgument('lpSelectorEntry', FunctionArgument.ADDRESS)
    ]

    def __wow64_get_thread_selector_entry(self, hThread, dwSelector, lpSelectorEntry):
        return self._wrap_results([
            FunctionResult(1, FunctionResult.NUMBER),
            self._new_address_result(target=lpSelectorEntry)
        ])

    __wow64_set_thread_context_arguments = [
        FunctionArgument('hThread', FunctionArgument.ADDRESS),
        FunctionArgument('lpContext', FunctionArgument.ADDRESS)
    ]

    def __wow64_set_thread_context(self, hThread, lpContext):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __wow64_suspend_thread_arguments = [
        FunctionArgument('hThread', FunctionArgument.ADDRESS)
    ]

    def __wow64_suspend_thread(self, hThread):
        result = FunctionResult(100, FunctionResult.NUMBER) # fake previous suspend count
        return self._wrap_results(result)

    __write_encrypted_file_raw_arguments = [
        FunctionArgument('pfImportCallback', FunctionArgument.ADDRESS),
        FunctionArgument('pvCallbackContext', FunctionArgument.ADDRESS),
        FunctionArgument('pvContext', FunctionArgument.ADDRESS)
    ]

    def __write_encrypted_file_raw(self, pfImportCallback, pvCallbackContext, pvContext):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __write_private_profile_section_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpString', FunctionArgument.STRING),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __write_private_profile_section_A(self, lpAppName, lpString, lpFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __write_private_profile_string_A_arguments= [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('lpString', FunctionArgument.STRING),
        FunctionArgument('lpFileName', FunctionArgument.STRING)
    ]

    def __write_private_profile_string_A(self, lpAppName, lpKeyName, lpString, lpFileName):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __write_private_profile_struct_A_arguments = [
        FunctionArgument('lpszSection', FunctionArgument.STRING),
        FunctionArgument('lpszKey', FunctionArgument.STRING),
        FunctionArgument('lpStruct', FunctionArgument.ADDRESS),
        FunctionArgument('uSizeStruct', FunctionArgument.NUMBER),
        FunctionArgument('szFile', FunctionArgument.STRING)
    ]

    def __write_private_profile_struct_A(self, lpszSection, lpszKey, lpStruct, uSizeStruct, szFile):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __write_profile_section_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __write_profile_section_A(self, lpAppName, lpString):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __write_profile_string_A_arguments = [
        FunctionArgument('lpAppName', FunctionArgument.STRING),
        FunctionArgument('lpKeyName', FunctionArgument.STRING),
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __write_profile_string_A(self, lpAppName, lpKeyName, lpString):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __write_tapemark_arguments = [
        FunctionArgument('hDevice', FunctionArgument.ADDRESS),
        FunctionArgument('dwTapemarkType', FunctionArgument.NUMBER),
        FunctionArgument('dwTapemarkCount', FunctionArgument.NUMBER),
        FunctionArgument('bImmediate', FunctionArgument.NUMBER)
    ]

    def __write_tapemark(self, hDevice, dwTapemarkType, dwTapemarkCount, bImmediate):
        result = FunctionResult(0, FunctionResult.NUMBER)
        return self._wrap_results(result)

    __WTS_get_active_console_session_id_arguments = []

    def __WTS_get_active_console_session_id(self):
        result = FunctionResult(3, FunctionResult.NUMBER) # fake session id
        return self._wrap_results(result)

    __zombify_act_ctx_arguments = [
        FunctionArgument('hActCtx', FunctionArgument.ADDRESS)
    ]

    def __zombify_act_ctx(self, hActCtx):
        return self._wrap_results(self._true_result())
    