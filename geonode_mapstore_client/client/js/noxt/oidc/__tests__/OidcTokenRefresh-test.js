/*
 * Copyright 2026, GeoSolutions Sas.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

import expect from 'expect';
import { OIDC_REFRESH_MARGIN_MS, getOidcAccessTokenExpiresAt } from '../OidcTokenUtils';
import { startOidcTokenRefresh } from '../OidcTokenRefresh';

const makeAccessToken = (expiresAt) => {
    const payload = btoa(JSON.stringify({ exp: expiresAt }))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    return `header.${payload}.signature`;
};

describe('OIDC token refresh manager', () => {
    it('schedules one refresh from token expiry with the configured safety margin', () => {
        const saved = {
            setTimeout: window.setTimeout,
            clearTimeout: window.clearTimeout,
            addEventListener: window.addEventListener,
            removeEventListener: window.removeEventListener
        };
        const scheduled = [];
        window.setTimeout = (callback, delay) => {
            scheduled.push({ callback, delay });
            return scheduled.length;
        };
        window.clearTimeout = () => {};
        window.addEventListener = () => {};
        window.removeEventListener = () => {};

        try {
            const token = makeAccessToken(Math.floor(Date.now() / 1000) + 3600);
            const expiresAt = getOidcAccessTokenExpiresAt(token);
            const store = {
                dispatch: () => {},
                getState: () => ({ security: { token } })
            };
            const stop = startOidcTokenRefresh({ enabled: true }, token, store);

            expect(scheduled.length).toBe(1);
            const targetRefreshTime = expiresAt - OIDC_REFRESH_MARGIN_MS + 5000;
            expect(Math.abs(Date.now() + scheduled[0].delay - targetRefreshTime)).toBeLessThan(1500);

            stop();
        } finally {
            window.setTimeout = saved.setTimeout;
            window.clearTimeout = saved.clearTimeout;
            window.addEventListener = saved.addEventListener;
            window.removeEventListener = saved.removeEventListener;
        }
    });
});
