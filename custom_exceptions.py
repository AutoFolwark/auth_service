from rfc9457 import ConflictProblem, Problem, UnauthorisedProblem, ForbiddenProblem, BadRequestProblem
from fastapi import Request, Response

class RegisteredWithPresentCredentialsProblem(ConflictProblem):
    title = "User already registered with present credentials"

class TooManyRequests(Problem):
    type = "too-many-requests"
    status = 429
    title = "Too many requests"
    detail = "Too many requests"

async def raise_rate_limiter_error(request: Request, response: Response, pexpire: int):
    raise TooManyRequests(
        status=429,
        title="Too many requests",
        detail=f"Too many requests, try after {pexpire // 1000} seconds"
    )

class EmailNotVerifiedProblem(UnauthorisedProblem):
    type = "email-not-verified"
    title = "Email not verified"

class PhoneNotVerifiedProblem(UnauthorisedProblem):
    type = "phone-not-verified"
    title = "Phone not verified"

class UserDeactivatedProblem(ForbiddenProblem):
    type = "user-deactivated"
    title = "User deactivated"

class InvalidCodeProblem(BadRequestProblem):
    type = "invalid-code"
    title = "Invalid code"

class NotEnoughPermissionsProblem(ForbiddenProblem):
    type = "not-enough-permissions"
    title = "Not enough permissions"
    detail = "Not enough permissions"


async def raise_code_rate_limiter_error(request: Request, response: Response, pexpire: int):
    raise TooManyRequests(
        status=429,
        title="Too many requests",
        detail=f"Too many requests, try after {pexpire // 1000} seconds, last sent code will be valid"
    )

