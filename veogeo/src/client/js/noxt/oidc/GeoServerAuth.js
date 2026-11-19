import { refreshSuccess } from '@mapstore/framework/actions/security';
import { getStore } from '@mapstore/framework/utils/StateUtils';
import {
    getOidcAccessToken,
    getOidcAccessTokenExpiresAt,
    refreshOidcAccessTokenIfNeeded
} from './OidcTokenUtils';

export const isSameOriginGeoServerRequest = (requestUrl, currentUrl) => {
    try {
        const page = new URL(currentUrl);
        const request = new URL(requestUrl, page);
        return request.origin === page.origin && /(?:^|\/)(?:geoserver|gs)(?:\/|$)/i.test(request.pathname);
    } catch (error) {
        return false;
    }
};

export const applyGeoServerBearerAuthorization = async(
    requestConfig,
    store,
    currentUrl = window.location.href,
    refreshTokenIfNeeded = refreshOidcAccessTokenIfNeeded,
    recoverAccessToken = getOidcAccessToken
) => {
    if (!isSameOriginGeoServerRequest(requestConfig.url, currentUrl)) return requestConfig;

    const security = store?.getState()?.security;
    const oidcConfig = security?.user?.oidc_config;
    let accessToken = security?.token;
    if (!oidcConfig?.enabled) return requestConfig;

    let recoveryAttempted = false;
    let tokenSet;
    const recoverFromProviderSession = async() => {
        recoveryAttempted = true;
        tokenSet = await recoverAccessToken(oidcConfig, { allowSilentAuthorization: true });
        if (tokenSet?.access_token) {
            accessToken = tokenSet.access_token;
            store?.dispatch?.(refreshSuccess({
                access_token: tokenSet.access_token,
                refresh_token: tokenSet.refresh_token,
                expires: tokenSet.expires_in
            }, 'oidc'));
            tokenSet = undefined;
        }
    };

    if (accessToken) {
        try {
            tokenSet = await refreshTokenIfNeeded(oidcConfig, accessToken);
        } catch (error) {
            const expiresAt = getOidcAccessTokenExpiresAt(accessToken);
            if (!expiresAt || expiresAt <= Date.now()) await recoverFromProviderSession();
        }
        if (tokenSet?.access_token) {
            accessToken = tokenSet.access_token;
            store?.dispatch?.(refreshSuccess({
                access_token: tokenSet.access_token,
                refresh_token: tokenSet.refresh_token,
                expires: tokenSet.expires_in
            }, 'oidc'));
        }
    } else {
        await recoverFromProviderSession();
    }

    let expiresAt = getOidcAccessTokenExpiresAt(accessToken);
    if ((!expiresAt || expiresAt <= Date.now()) && !recoveryAttempted) {
        await recoverFromProviderSession();
        expiresAt = getOidcAccessTokenExpiresAt(accessToken);
    }
    if (!expiresAt || expiresAt <= Date.now()) {
        throw new Error('A valid OIDC access token is required for GeoServer Cloud requests.');
    }

    return {
        ...requestConfig,
        headers: {
            ...(requestConfig.headers || {}),
            Authorization: `Bearer ${accessToken}`
        }
    };
};

let interceptorId;

export const installGeoServerOidcRequestInterceptor = (axios) => {
    if (interceptorId !== undefined) axios.interceptors.request.eject(interceptorId);
    interceptorId = axios.interceptors.request.use((requestConfig) =>
        applyGeoServerBearerAuthorization(requestConfig, getStore())
    );
};
