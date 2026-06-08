# Re-export security utilities so that
#   from src.api.security import verify_api_key
# works regardless of whether security is treated as a package or module.
from src.api.security_module import verify_api_key, API_KEY, api_key_header  # noqa: F401
