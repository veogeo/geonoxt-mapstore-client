import { refreshSuccess } from '@mapstore/framework/actions/security';
import { getStore } from '@mapstore/framework/utils/StateUtils';
import {
    getOidcAccessToken,
    getOidcAccessTokenExpiresAt,
    refreshOidcAccessTokenIfNeeded
} from './OidcTokenUtils';

export const isSameOriginGeoServerRequest = (requestUrl, currentUrl, geoserverPublicLocation) => {
    try {
        const page = new URL(currentUrl);
        const request = new URL(requestUrl, page);
        if (request.origin !== page.origin) return false;

        if (!geoserverPublicLocation) {
            return /(?:^|\/)geoserver(?:\/|$)/i.test(request.pathname);
        }

        const geoserver = new URL(geoserverPublicLocation, page);
        const basePath = geoserver.pathname.replace(/\/+$/, '');
        if (geoserver.origin !== page.origin || !basePath || basePath === '/') return false;

        return request.pathname === basePath || request.pathname.startsWith(basePath + '/');
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
    const security = store?.getState()?.security;
    const oidcConfig = security?.user?.oidc_config;
    if (!oidcConfig?.enabled || !isSameOriginGeoServerRequest(
        requestConfig.url,
        currentUrl,
        oidcConfig.geoserver_public_location
    )) return requestConfig;

    let accessToken = security?.token;

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
