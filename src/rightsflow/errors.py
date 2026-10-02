class RightsFlowError(Exception):
    code = "internal_error"
    status = 500


class ValidationError(RightsFlowError):
    code = "validation_error"
    status = 400

    def __init__(self, message: str, error_code: str | None = None):
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