from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class OIDCClientConfigView(APIView):
    """Expose the public OIDC client configuration used by this MapStore fork."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        if not getattr(settings, "NOXT_GEOSERVER_CLOUD_ENABLED", False):
            return Response({"enabled": False}, headers={"Cache-Control": "no-store"})

        return Response(
            {
                "enabled": True,
                "client_id": settings.NOXT_MAPSTORE_OIDC_CLIENT_ID,
                "discovery_uri": settings.NOXT_MAPSTORE_OIDC_DISCOVERY_URI,
                "redirect_uri": settings.NOXT_MAPSTORE_OIDC_REDIRECT_URI,
                "audience": settings.NOXT_GEOSERVER_CLOUD_AUDIENCE,
                "resource": settings.NOXT_MAPSTORE_OIDC_RESOURCE,
                "scopes": settings.NOXT_MAPSTORE_OIDC_SCOPES,
            },
            headers={"Cache-Control": "no-store"},
        )
