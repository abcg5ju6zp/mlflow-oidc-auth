"""Admin API for OIDC client-credential generations.

Two endpoints, both administrator-only:

* ``POST .../providers/{provider_id}/refresh`` — re-read the provider's credentials from the
  configured secret backend, validate new material, and publish a new generation when something
  changed. Safe to retry and safe for several workers to call at once: the result reflects the
  single committed generation.
* ``GET .../providers/{provider_id}/generations`` — inspect the active and retired generations
  without their secrets.

No response ever contains a client secret or its ciphertext; fingerprints appear as short
prefixes only.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from mlflow_oidc_auth.credentials import generations as credential_generations
from mlflow_oidc_auth.credentials.generations import (
    REASON_CLEANUP,
    REASON_CONFLICT,
    REASON_DISCOVERY,
    REASON_INVALID_CONFIG,
    REASON_INVALID_CREDENTIALS,
    REASON_UNKNOWN_PROVIDER,
    RESULT_FAILED,
)
from mlflow_oidc_auth.dependencies import check_admin_permission
from mlflow_oidc_auth.logger import get_logger
from mlflow_oidc_auth.routers._prefix import _get_rest_path
from mlflow_oidc_auth.repository.credential_generation import CredentialGeneration

logger = get_logger()

OIDC_CREDENTIALS_ROUTER_PREFIX = _get_rest_path("/mlflow/oidc/credentials")

_RESPONSES = {
    403: {"description": "Forbidden - administrator privileges required"},
    404: {"description": "Unknown provider"},
    409: {"description": "A concurrent refresh committed different credentials"},
    422: {"description": "The new credentials failed validation"},
    500: {"description": "The rotation could not be committed"},
    503: {"description": "The current configuration is not usable"},
}

oidc_credentials_router = APIRouter(prefix=OIDC_CREDENTIALS_ROUTER_PREFIX, tags=["oidc credentials"], responses=_RESPONSES)

REFRESH_PROVIDER = "/providers/{provider_id}/refresh"
LIST_GENERATIONS = "/providers/{provider_id}/generations"

#: Failure reason → HTTP status.
_FAILURE_STATUS = {
    REASON_UNKNOWN_PROVIDER: 404,
    REASON_INVALID_CREDENTIALS: 422,
    REASON_DISCOVERY: 422,
    REASON_CONFLICT: 409,
    REASON_CLEANUP: 500,
    REASON_INVALID_CONFIG: 503,
}


def _generation_payload(generation: Optional[CredentialGeneration]) -> Optional[dict]:
    """Non-secret view of one generation, suitable for an API response."""
    if generation is None:
        return None
    return {
        "generation_id": generation.generation_id,
        "status": generation.status,
        "client_id": generation.client_id,
        "discovery_url": generation.discovery_url,
        "fingerprint_prefix": generation.fingerprint[:8],
        "effective_at": generation.effective_at.isoformat() if generation.effective_at else None,
        "retired_at": generation.retired_at.isoformat() if generation.retired_at else None,
        "retain_until": generation.retain_until.isoformat() if generation.retain_until else None,
    }


@oidc_credentials_router.post(REFRESH_PROVIDER)
async def refresh_provider_credentials(request: Request, provider_id: str, username: str = Depends(check_admin_permission)):
    """Refresh one provider's credentials and publish a generation when they changed.

    Returns the same result for a retried or concurrent call with identical material. A failure
    response means the active generation is unchanged.
    """
    result = await credential_generations.publish_refresh(provider_id, actor=username)
    if result.result == RESULT_FAILED:
        status_code = _FAILURE_STATUS.get(result.reason, 500)
        raise HTTPException(
            status_code=status_code,
            detail={
                "provider_id": provider_id,
                "result": RESULT_FAILED,
                "reason": result.reason,
                "active_generation_id": result.active.generation_id if result.active else None,
            },
        )

    return JSONResponse(
        {
            "provider_id": provider_id,
            "result": result.result,
            "active": _generation_payload(result.active),
            "retired_generation_id": result.retired_generation_id,
            "pruned_generation_ids": list(result.pruned_generation_ids),
        }
    )


@oidc_credentials_router.get(LIST_GENERATIONS)
async def list_provider_generations(request: Request, provider_id: str, username: str = Depends(check_admin_permission)):
    """List a provider's generations (active first), never including any secret material."""
    if not credential_generations.provider_is_refreshable(provider_id):
        raise HTTPException(status_code=404, detail=f"Unknown OIDC provider: {provider_id}")
    generations = credential_generations.list_generations(provider_id)
    return JSONResponse(
        {
            "provider_id": provider_id,
            "generations": [_generation_payload(generation) for generation in generations],
        }
    )
