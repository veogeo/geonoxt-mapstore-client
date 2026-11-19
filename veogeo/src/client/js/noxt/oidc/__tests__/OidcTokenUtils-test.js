/*
 * Copyright 2026, GeoSolutions Sas.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

import expect from 'expect';
import {
    getOidcAccessTokenExpiresAt,
    refreshOidcAccessTokenIfNeeded
} from '../OidcTokenUtils';

const makeAccessToken = (expiresAt) => {
    const payload = btoa(JSON.stringify({ exp: expiresAt }))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    return `header.${payload}.signature`;
};

describe('OIDC token utilities', () => {
    it('reads the access token expiration from its JWT payload', () => {
        const expiresAt = Math.floor(Date.now() / 1000) + 3600;
        expect(getOidcAccessTokenExpiresAt(makeAccessToken(expiresAt))).toBe(expiresAt * 1000);
    });

    it('does not request OIDC discovery while the access token is outside the refresh margin', async() => {
        const originalFetch = window.fetch;
        let discoveryRequested = false;
        window.fetch = () => {
            discoveryRequested = true;
            return Promise.reject(new Error('Unexpected discovery request'));
        };

        try {
            const token = makeAccessToken(Math.floor(Date.now() / 1000) + 3600);
            const result = await refreshOidcAccessTokenIfNeeded({ enabled: true }, token);
            expect(result).toBe(null);
            expect(discoveryRequested).toBe(false);
        } finally {
            window.fetch = originalFetch;
        }
    });

    it('shares one rotating refresh request between concurrent GeoServer requests', async() => {
        const originalFetch = window.fetch;
        const issuer = 'https://issuer.example.test/';
        const currentToken = makeAccessToken(Math.floor(Date.now() / 1000) + 30);
        const refreshedToken = (() => {
            const payload = btoa(JSON.stringify({
                exp: Math.floor(Date.now() / 1000) + 3600,
                iss: issuer,
                aud: 'geoserver-cloud'
            })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
            return `header.${payload}.signature`;
        })();
        const config = {
            enabled: true,
            client_id: 'mapstore-client',
            discovery_uri: 'https://issuer.example.test/.well-known/openid-configuration/',
            redirect_uri: 'http://localhost/catalogue/',
            audience: 'geoserver-cloud'
        };
        const storageKey = `geonode:oidc:token:${encodeURIComponent(issuer)}:${encodeURIComponent(config.client_id)}`;
        sessionStorage.setItem(storageKey, JSON.stringify({
            access_token: currentToken,
            refresh_token: 'old-refresh-token',
            expires_at: Date.now() - 1000
        }));
        let discoveryRequests = 0;
        let tokenRequests = 0;
        window.fetch = (requestUrl) => {
            if (String(requestUrl) === config.discovery_uri) {
                discoveryRequests += 1;
                return Promise.resolve({
                    ok: true,
                    json: () => Promise.resolve({
                        issuer,
                        authorization_endpoint: `${issuer}authorize`,
                        token_endpoint: `${issuer}token`
                    })
                });
            }
            tokenRequests += 1;
            return Promise.resolve({
                ok: true,
                json: () => Promise.resolve({
                    access_token: refreshedToken,
                    refresh_token: 'rotated-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer'
                })
            });
        };

        try {
            const results = await Promise.all([
                refreshOidcAccessTokenIfNeeded(config, currentToken),
                refreshOidcAccessTokenIfNeeded(config, currentToken)
            ]);
            expect(discoveryRequests).toBe(1);
            expect(tokenRequests).toBe(1);
            expect(results[0].access_token).toBe(refreshedToken);
            expect(results[1].access_token).toBe(refreshedToken);
        } finally {
            window.fetch = originalFetch;
            sessionStorage.removeItem(storageKey);
        }
    });
});
