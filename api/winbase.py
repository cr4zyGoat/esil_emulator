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
            "DebugSetProcessKillOnExit": [self.__debug_set_process_kill_on_exit, self.__debug_set_process_kill_on_exit_arguments],
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
