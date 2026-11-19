import expect from 'expect';
import { refreshSuccess } from '@mapstore/framework/actions/security';
import {
    applyGeoServerBearerAuthorization,
    isSameOriginGeoServerRequest
} from '../GeoServerAuth';

const makeAccessToken = (expiresAt) => {
    const payload = btoa(JSON.stringify({ exp: expiresAt }))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    return `header.${payload}.signature`;
};

describe('GeoServer OIDC request authentication', () => {
    it('matches only same-origin GeoServer and GeoServer alias paths', () => {
        expect(isSameOriginGeoServerRequest('/geoserver/wfs', 'http://localhost/catalogue/')).toBe(true);
        expect(isSameOriginGeoServerRequest('/gs/wfs', 'http://localhost/catalogue/')).toBe(true);
        expect(isSameOriginGeoServerRequest('https://other.example/geoserver/wfs', 'http://localhost/')).toBe(false);
        expect(isSameOriginGeoServerRequest('/api/v2/datasets', 'http://localhost/')).toBe(false);
    });

    it('adds the current OIDC JWT only to same-origin GeoServer requests', async() => {
        const token = makeAccessToken(Math.floor(Date.now() / 1000) + 3600);
        const store = {
            getState: () => ({ security: { token, user: { oidc_config: { enabled: true } } } }),
            dispatch: () => {}
        };
        const request = await applyGeoServerBearerAuthorization(
            { url: '/geoserver/wfs', headers: { 'Content-Type': 'application/xml' } },
            store,
            'http://localhost/catalogue/'
        );
        expect(request.headers.Authorization).toBe(`Bearer ${token}`);

        const apiRequest = { url: '/api/v2/datasets', headers: {} };
        expect(await applyGeoServerBearerAuthorization(apiRequest, store, 'http://localhost/')).toBe(apiRequest);
    });

    it('recovers a missing Redux token through the active OIDC provider session', async() => {
        const recoveredToken = makeAccessToken(Math.floor(Date.now() / 1000) + 3600);
        const store = {
            getState: () => ({ security: { user: { oidc_config: { enabled: true } } } }),
            dispatch: () => {}
        };
        let recoveryOptions;
        const request = await applyGeoServerBearerAuthorization(
            { url: '/geoserver/wfs', headers: {} },
            store,
            'http://localhost/catalogue/',
            () => Promise.resolve(null),
            (_config, options) => {
                recoveryOptions = options;
                return Promise.resolve({ access_token: recoveredToken, expires_in: 3600 });
            }
        );
        expect(request.headers.Authorization).toBe(`Bearer ${recoveredToken}`);
        expect(recoveryOptions).toEqual({ allowSilentAuthorization: true });
    });

    it('recovers an expired token from the provider session after refresh fails', async() => {
        const expiredToken = makeAccessToken(Math.floor(Date.now() / 1000) - 30);
        const recoveredToken = makeAccessToken(Math.floor(Date.now() / 1000) + 3600);
        const store = {
            getState: () => ({ security: { token: expiredToken, user: { oidc_config: { enabled: true } } } }),
            dispatch: () => {}
        };
        const request = await applyGeoServerBearerAuthorization(
            { url: '/gs/wfs', headers: {} },
            store,
            'http://localhost/catalogue/',
            () => Promise.reject(new Error('Refresh token rejected')),
            () => Promise.resolve({ access_token: recoveredToken, expires_in: 3600 })
        );
        expect(request.headers.Authorization).toBe(`Bearer ${recoveredToken}`);
    });

    it('uses and publishes a refreshed OIDC token before sending the request', async() => {
        const currentToken = makeAccessToken(Math.floor(Date.now() / 1000) + 30);
        const refreshedToken = makeAccessToken(Math.floor(Date.now() / 1000) + 3600);
        const dispatched = [];
        const store = {
            getState: () => ({ security: { token: currentToken, user: { oidc_config: { enabled: true } } } }),
            dispatch: (action) => dispatched.push(action)
        };
        const refreshTokenIfNeeded = () => Promise.resolve({
            access_token: refreshedToken,
            refresh_token: 'rotated-refresh-token',
            expires_in: 3600
        });

        const request = await applyGeoServerBearerAuthorization(
            { url: '/geoserver/wfs', headers: {} },
            store,
            'http://localhost/catalogue/',
            refreshTokenIfNeeded
        );
        expect(request.headers.Authorization).toBe(`Bearer ${refreshedToken}`);
        expect(dispatched[0]).toEqual(refreshSuccess({
            access_token: refreshedToken,
            refresh_token: 'rotated-refresh-token',
            expires: 3600
        }, 'oidc'));
    });
});
