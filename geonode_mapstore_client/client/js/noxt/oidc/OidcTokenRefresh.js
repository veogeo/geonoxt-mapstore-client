import { refreshSuccess } from '@mapstore/framework/actions/security';
import {
    getOidcAccessTokenExpiresAt,
    OIDC_REFRESH_MARGIN_MS,
    refreshOidcAccessTokenIfNeeded
} from './OidcTokenUtils';

const OIDC_REFRESH_SCHEDULING_BUFFER_MS = 5 * 1000;
const OIDC_REFRESH_RETRY_BASE_MS = 30 * 1000;
const OIDC_REFRESH_RETRY_MAX_MS = 5 * 60 * 1000;
const MAX_TIMEOUT_MS = 2147483647;

/**
 * Keep MapStore's OIDC access token current without polling discovery.
 * Returns a cleanup function for consumers that destroy the store.
 */
export const startOidcTokenRefresh = (config, initialAccessToken, store) => {
    if (!config?.enabled || !initialAccessToken || !store?.dispatch) return () => {};

    let refreshTimer;
    let retryAttempt = 0;
    let active = true;
    const getCurrentAccessToken = () => store.getState()?.security?.token || initialAccessToken;
    let refreshIfNeeded;
    const clearRefreshTimer = () => {
        if (refreshTimer !== undefined) {
            window.clearTimeout(refreshTimer);
            refreshTimer = undefined;
        }
    };
    const scheduleRefresh = (accessToken, delayOverride) => {
        clearRefreshTimer();
        if (!active) return;
        const expiresAt = getOidcAccessTokenExpiresAt(accessToken);
        if (!expiresAt && delayOverride === undefined) {
            console.warn('Could not schedule OIDC token refresh: access token has no readable expiry.');
            return;
        }
        const untilRefresh = expiresAt
            ? Math.max(1000, expiresAt - Date.now() - OIDC_REFRESH_MARGIN_MS + OIDC_REFRESH_SCHEDULING_BUFFER_MS)
            : delayOverride;
        const delay = Math.min(delayOverride ?? untilRefresh, MAX_TIMEOUT_MS);
        refreshTimer = window.setTimeout(refreshIfNeeded, delay);
    };
    const scheduleRetry = (accessToken) => {
        const delay = Math.min(
            OIDC_REFRESH_RETRY_BASE_MS * (2 ** retryAttempt),
            OIDC_REFRESH_RETRY_MAX_MS
        );
        retryAttempt += 1;
        scheduleRefresh(accessToken, delay);
    };
    refreshIfNeeded = async() => {
        if (!active) return;
        try {
            const tokenSet = await refreshOidcAccessTokenIfNeeded(config, getCurrentAccessToken());
            if (!active) return;
            if (tokenSet?.access_token) {
                store.dispatch(refreshSuccess({
                    access_token: tokenSet.access_token,
                    refresh_token: tokenSet.refresh_token,
                    expires: tokenSet.expires_in
                }, 'oidc'));
                retryAttempt = 0;
                scheduleRefresh(tokenSet.access_token);
                return;
            }
            const currentAccessToken = getCurrentAccessToken();
            const currentExpiresAt = getOidcAccessTokenExpiresAt(currentAccessToken);
            if (currentExpiresAt && currentExpiresAt > Date.now() + OIDC_REFRESH_MARGIN_MS) {
                retryAttempt = 0;
                scheduleRefresh(currentAccessToken);
                return;
            }
            scheduleRetry(currentAccessToken);
        } catch (error) {
            console.error('Could not refresh the OIDC access token.', error);
            scheduleRetry(getCurrentAccessToken());
        }
    };
    const onPageHide = () => {
        active = false;
        clearRefreshTimer();
    };
    const onPageShow = (event) => {
        if (event.persisted) {
            active = true;
            retryAttempt = 0;
            scheduleRefresh(getCurrentAccessToken());
        }
    };

    scheduleRefresh(getCurrentAccessToken());
    window.addEventListener('pagehide', onPageHide);
    window.addEventListener('pageshow', onPageShow);

    return () => {
        active = false;
        clearRefreshTimer();
        window.removeEventListener('pagehide', onPageHide);
        window.removeEventListener('pageshow', onPageShow);
    };
};
