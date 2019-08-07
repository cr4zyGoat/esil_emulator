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

            'FindAtomA': [self.__find_atom_A, self.__find_atom_A_arguments],
            'GetAtomNameA': [self.__get_atom_name_A, self.__get_atom_name_A_arguments]
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
        if os.path.isfile(pFileName) and util.is_pe_file(pFileName):
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

    __find_atom_A_arguments = [
        FunctionArgument('lpString', FunctionArgument.STRING)
    ]

    def __find_atom_A(self, lpString):
        atom = self.__atoms_table.find_atom(lpString)
        result = FunctionResult(atom, FunctionResult.NUMBER)
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
