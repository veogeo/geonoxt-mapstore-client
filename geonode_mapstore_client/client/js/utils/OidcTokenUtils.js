const FLOW_KEY = 'geonode:oidc:flow';
const TOKEN_KEY_PREFIX = 'geonode:oidc:token:';
const REFRESH_MARGIN_MS = 90 * 1000;

const encodeBase64Url = (value) => {
    let bytes;
    if (value instanceof Uint8Array) {
        bytes = value;
    } else if (value instanceof ArrayBuffer) {
        bytes = new Uint8Array(value);
    } else if (ArrayBuffer.isView(value)) {
        bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    } else {
        bytes = new TextEncoder().encode(String(value));
    }
    let binary = '';
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

const randomValue = (length = 32) => {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return encodeBase64Url(bytes);
};

const decodeJwtPayload = (token) => {
    const parts = token?.split('.');
    if (!parts || parts.length !== 3) {
        throw new Error('The active OIDC provider did not issue a JWT access token.');
    }
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64.padEnd(base64.length + ((4 - base64.length % 4) % 4), '=')));
};

// Check routing claims here; the gateway verifies the JWT signature and full token validity.
const validateAccessTokenClaims = (accessToken, issuer, audience) => {
    const claims = decodeJwtPayload(accessToken);
    const now = Math.floor(Date.now() / 1000);
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== issuer || !audiences.includes(audience) || !claims.exp || claims.exp <= now) {
        throw new Error('The access token issuer, audience, or expiry does not match GeoServer Cloud.');
    }
    return claims;
};

const loadDiscovery = async (discoveryUri) => {
    const response = await fetch(discoveryUri, { cache: 'no-store', credentials: 'omit' });
    if (!response.ok) {
        throw new Error(`OIDC discovery failed with HTTP ${response.status}.`);
    }
    const discovery = await response.json();
    if (!discovery.issuer || !discovery.authorization_endpoint || !discovery.token_endpoint) {
        throw new Error('OIDC discovery is missing issuer, authorization, or token endpoint metadata.');
    }
    return discovery;
};

const tokenStorageKey = (config, discovery) =>
    TOKEN_KEY_PREFIX + encodeURIComponent(discovery.issuer) + ':' + encodeURIComponent(config.client_id);

const readStoredValue = (key) => {
    try {
        return JSON.parse(sessionStorage.getItem(key) || 'null');
    } catch (error) {
        sessionStorage.removeItem(key);
        return null;
    }
};

const storeTokenSet = (key, response, config, discovery, previous = {}) => {
    if (response.token_type && response.token_type.toLowerCase() !== 'bearer') {
        throw new Error('The active OIDC provider returned a non-Bearer access token.');
    }
    const claims = validateAccessTokenClaims(response.access_token, discovery.issuer, config.audience);
    const now = Math.floor(Date.now() / 1000);
    const claimLifetime = Math.max(0, claims.exp - now);
    const responseLifetime = Number(response.expires_in);
    const expiresIn = responseLifetime > 0 ? Math.min(responseLifetime, claimLifetime) : claimLifetime;
    const tokenSet = {
        access_token: response.access_token,
        refresh_token: response.refresh_token || previous.refresh_token || null,
        expires_at: Math.min(Date.now() + expiresIn * 1000, claims.exp * 1000),
        expires_in: expiresIn
    };
    sessionStorage.setItem(key, JSON.stringify(tokenSet));
    return tokenSet;
};

const postTokenRequest = async (discovery, parameters) => {
    const body = new URLSearchParams(parameters);
    const response = await fetch(discovery.token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
        cache: 'no-store',
        credentials: 'omit'
    });
    const payload = await response.json();
    if (!response.ok || payload.error) {
        const error = new Error(payload.error_description || payload.error || `OIDC token request failed with HTTP ${response.status}.`);
        error.code = payload.error;
        throw error;
    }
    return payload;
};

const beginAuthorization = async (config, discovery, storageKey) => {
    const state = randomValue();
    const verifier = randomValue(48);
    const challenge = encodeBase64Url(await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const currentUrl = new URL(window.location.href);
    const authorizationUrl = new URL(discovery.authorization_endpoint);
    const parameters = {
        client_id: config.client_id,
        response_type: 'code',
        redirect_uri: config.redirect_uri,
        scope: config.scopes || 'groups',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        prompt: 'none'
    };
    if (config.resource) parameters.resource = config.resource;
    sessionStorage.setItem(FLOW_KEY, JSON.stringify({
        state,
        verifier,
        return_url: currentUrl.href,
        storage_key: storageKey,
        config,
        discovery,
        silent: true
    }));
    authorizationUrl.search = new URLSearchParams(parameters).toString();
    window.location.assign(authorizationUrl.toString());
    return new Promise(() => {});
};

const finishAuthorization = async (config, discovery, storageKey) => {
    const url = new URL(window.location.href);
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    if (!code && !error) return null;

    const flow = readStoredValue(FLOW_KEY);
    if (!flow?.state
        || url.searchParams.get('state') !== flow.state
        || flow.storage_key !== storageKey
        || flow.config?.client_id !== config.client_id
        || flow.config?.redirect_uri !== config.redirect_uri) {
        throw new Error('OIDC state validation failed.');
    }
    if (error) {
        sessionStorage.removeItem(FLOW_KEY);
        window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
        if (flow.silent && ['login_required', 'interaction_required', 'consent_required'].includes(error)) {
            return false;
        }
        throw new Error(url.searchParams.get('error_description') || error);
    }

    const parameters = {
        grant_type: 'authorization_code',
        client_id: config.client_id,
        redirect_uri: config.redirect_uri,
        code,
        code_verifier: flow.verifier
    };
    if (config.resource) parameters.resource = config.resource;
    let response;
    try {
        response = await postTokenRequest(discovery, parameters);
    } catch (tokenError) {
        sessionStorage.removeItem(FLOW_KEY);
        if (tokenError.code === 'invalid_grant') {
            window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
            return null;
        }
        throw tokenError;
    }
    const tokenSet = storeTokenSet(storageKey, response, config, discovery);
    sessionStorage.removeItem(FLOW_KEY);

    const returnUrl = new URL(flow.return_url || window.location.origin + '/', window.location.origin);
    if (returnUrl.origin !== window.location.origin) {
        throw new Error('OIDC return URL must remain on the GeoNode origin.');
    }
    window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
    if (returnUrl.href !== window.location.href) {
        window.location.replace(returnUrl.href);
        return new Promise(() => {});
    }
    return tokenSet;
};

export const getOidcAccessToken = async (config, { allowSilentAuthorization = false } = {}) => {
    if (!config?.enabled) return null;
    if (!config.client_id || !config.discovery_uri || !config.redirect_uri || !config.audience) {
        throw new Error('MapStore OIDC client configuration is incomplete.');
    }

    const discovery = await loadDiscovery(config.discovery_uri);
    const storageKey = tokenStorageKey(config, discovery);
    const callbackToken = await finishAuthorization(config, discovery, storageKey);
    if (callbackToken === false) return null;
    if (callbackToken) return callbackToken;

    const tokenSet = readStoredValue(storageKey);
    if (tokenSet?.access_token && tokenSet.expires_at > Date.now() + REFRESH_MARGIN_MS) {
        try {
            validateAccessTokenClaims(tokenSet.access_token, discovery.issuer, config.audience);
            return tokenSet;
        } catch (error) {
            sessionStorage.removeItem(storageKey);
        }
    }

    if (tokenSet?.refresh_token) {
        try {
            const parameters = {
                grant_type: 'refresh_token',
                client_id: config.client_id,
                refresh_token: tokenSet.refresh_token
            };
            if (config.resource) parameters.resource = config.resource;
            const response = await postTokenRequest(discovery, parameters);
            return storeTokenSet(storageKey, response, config, discovery, tokenSet);
        } catch (error) {
            if (tokenSet.expires_at > Date.now() + 30000) return tokenSet;
            sessionStorage.removeItem(storageKey);
        }
    }

    return allowSilentAuthorization ? beginAuthorization(config, discovery, storageKey) : null;
};

export const refreshOidcAccessTokenIfNeeded = async (config, currentAccessToken) => {
    if (!config?.enabled || !currentAccessToken) return null;

    const discovery = await loadDiscovery(config.discovery_uri);
    const storageKey = tokenStorageKey(config, discovery);
    const tokenSet = readStoredValue(storageKey);
    if (!tokenSet?.access_token) return getOidcAccessToken(config, { allowSilentAuthorization: true });
    if (tokenSet.expires_at > Date.now() + REFRESH_MARGIN_MS) return null;

    const refreshedTokenSet = await getOidcAccessToken(config, { allowSilentAuthorization: true });
    if (refreshedTokenSet?.access_token === tokenSet.access_token
        && refreshedTokenSet?.expires_at === tokenSet.expires_at) {
        return null;
    }
    return refreshedTokenSet;
};
