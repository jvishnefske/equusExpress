from fastapi import HTTPException, status

class UserNotFoundException(HTTPException):
    def __init__(self, detail="User not found."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class RoleNotFoundException(HTTPException):
    def __init__(self, detail="Role not found."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class PermissionNotFoundException(HTTPException):
    def __init__(self, detail="Permission not found."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class GroupNotFoundException(HTTPException):
    def __init__(self, detail="Group not found."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class PasskeyNotFoundException(HTTPException):
    def __init__(self, detail="Passkey not found for this user."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class MissingChallengeDataException(HTTPException):
    def __init__(self, detail="Missing challenge data in response."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class PasskeyRegistrationFailedException(HTTPException):
    def __init__(self, detail="Passkey registration failed."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class PasskeyAuthenticationFailedException(HTTPException):
    def __init__(self, detail="Passkey authentication failed."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class ReplayAttackDetectedException(HTTPException):
    def __init__(self, detail="Invalid sign count - possible replay attack."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class InvalidCredentialsException(HTTPException):
    def __init__(self, detail="Could not validate credentials."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


class IncorrectCredentialsException(HTTPException):
    def __init__(self, detail="Incorrect username or password."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class AccountLockedException(HTTPException):
    def __init__(self, detail="Account is locked due to too many failed attempts."):
        super().__init__(status_code=status.HTTP_423_LOCKED, detail=detail)


class AccountDisabledException(HTTPException):
    def __init__(self, detail="Account is disabled."):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class PermissionNotDefinedException(HTTPException):
    def __init__(self, permission_name: str):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Permission '{permission_name}' not defined.")


class ForbiddenException(HTTPException):
    def __init__(self, detail="Forbidden: You do not have permission to perform this action."):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class SuperAdminCreationForbiddenException(HTTPException):
    def __init__(self, detail="Super admin can only be created as the first user."):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class UsernameAlreadyRegisteredException(HTTPException):
    def __init__(self, detail="Username already registered."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class FrontendFileNotFoundException(HTTPException):
    def __init__(self, detail="admin_portal_frontend.html not found."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class RoleNameAlreadyExistsException(HTTPException):
    def __init__(self, detail="Role name already exists."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class LastSuperAdminRoleDeletionForbiddenException(HTTPException):
    def __init__(self, detail="Cannot delete the last 'Super Administrator' role definition or if it's assigned to any user."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class SelfAccountStatusModificationForbiddenException(HTTPException):
    def __init__(self, detail="Cannot modify your own account status."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class SelfDeletionForbiddenException(HTTPException):
    def __init__(self, detail="Cannot delete your own account."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class LastSuperAdminDeletionForbiddenException(HTTPException):
    def __init__(self, detail="Cannot delete the last super administrator."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class IncorrectCurrentPasswordException(HTTPException):
    def __init__(self, detail="Current password is incorrect."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class RoleAlreadyExistsException(HTTPException):
    def __init__(self, detail="Role already exists."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class PermissionAlreadyAssignedException(HTTPException):
    def __init__(self, detail="Permission already assigned to role."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class RoleAlreadyAssignedToUserException(HTTPException):
    def __init__(self, detail="Role already assigned to user."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class LastSuperAdminRoleRemovalForbiddenException(HTTPException):
    def __init__(self, detail="Cannot remove Super Administrator role from the last super admin."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class GroupNameAlreadyExistsException(HTTPException):
    def __init__(self, detail="Group name already exists."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class GroupAlreadyExistsException(HTTPException):
    def __init__(self, detail="Group already exists."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class UserAlreadyAssignedToGroupException(HTTPException):
    def __init__(self, detail="User already assigned to group."):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class UserNotInGroupException(HTTPException):
    def __init__(self, detail="User is not in this group."):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


class InvalidEmergencyCodeException(HTTPException):
    def __init__(self, detail="Invalid emergency code."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
