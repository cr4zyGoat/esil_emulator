from api.base import ApiBase
from api.parameters import *
from api import winbase_objects as wbo

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
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

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

    def __add_conditional_ace(self):
        result = FunctionResult(1, FunctionResult.NUMBER)
        return self._wrap_results(result)

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
