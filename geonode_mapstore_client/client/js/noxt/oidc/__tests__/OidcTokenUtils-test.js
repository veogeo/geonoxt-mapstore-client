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
});
