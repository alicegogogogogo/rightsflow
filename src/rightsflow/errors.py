class RightsFlowError(Exception):
    code = "internal_error"
    status = 500


class ValidationError(RightsFlowError):
    code = "validation_error"
    status = 400


class CodedValidationError(ValidationError):
    """A 400 validation_error carrying a machine-readable detail code."""

    def __init__(self, error_code: str, message: str):
        super().__init__(message)
        self.error_code = error_code


class NotFoundError(RightsFlowError):
    code = "not_found"
    status = 404


class ConflictError(RightsFlowError):
    code = "conflict"
    status = 409


class IllegalTransitionError(ConflictError):
    """A state-machine rejection; the message always lists the legal successors."""

    code = "illegal_transition"
    status = 409