import re

from django.conf import settings
from geonode.base.auth import get_or_create_token
from .registry import BaseRequestConfigurationRuleHandler



class BaseConfigurationRuleHandler(BaseRequestConfigurationRuleHandler):
    """
    Base handler for configuration rules.
    """

    def get_rules(self, request):
        user = request.user
        if not user.is_authenticated:
            return []

        if getattr(settings, "NOXT_GEOSERVER_CLOUD_ENABLED", False):
            ogc_server = getattr(settings, "OGC_SERVER", {}).get("default", {})
            ogc_public_location = ogc_server.get("PUBLIC_LOCATION")
            if not ogc_public_location:
                return []
            ogc_base_url = re.escape(ogc_public_location.rstrip("/"))
            rules = [
                {
                    "urlPattern": (
                        f"^{ogc_base_url}/(?:[^/?#]+/)*(?:ows|wms|wfs|wcs|wps)/?(?:[?#].*)?$"
                    ),
                    "headers": {"Authorization": "Bearer ${securityToken}"},
                }
            ]
            geonode_base_url = re.escape(getattr(settings, "SITEURL", "").rstrip("/"))
            if getattr(settings, "SITEURL", ""):
                rules.append(
                    {
                        # MapStore API calls commonly use relative /api/v2 URLs;
                        # allow those and absolute same-origin URLs only.
                        "urlPattern": f"^(?:{geonode_base_url})?/api/v2(?:/.*)?(?:[?#].*)?$",
                        "headers": {"Authorization": "Bearer ${securityToken}"},
                    }
                )
            return rules

        rules = []
        token_obj = get_or_create_token(user)
        access_token = token_obj.token

        rules.extend(
            [
                {
                    "urlPattern": f"{settings.GEOSERVER_WEB_UI_LOCATION.rstrip('/')}/.*",
                    "params": {"access_token": access_token},
                },
                {"urlPattern": f"{settings.SITEURL.rstrip('/')}/gs.*", "params": {"access_token": access_token}},
                {
                    "urlPattern": f"{settings.SITEURL.rstrip('/')}/api/v2.*",
                    "headers": {"Authorization": f"Bearer {access_token}"},
                },
            ]
        )

        return rules
