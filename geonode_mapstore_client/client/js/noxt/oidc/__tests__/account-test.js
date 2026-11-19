import expect from 'expect';
import { getOidcAccountInfo } from '../account';

describe('GeoNoXT OIDC account adapter', () => {
    it('uses GeoNode session info and attaches the OIDC token for refresh', async() => {
        const token = { access_token: 'access-token' };
        const config = { enabled: true, client_id: 'client' };
        const getToken = async() => token;
        const getSession = async() => ({ sub: '17', preferred_username: 'alice', access_token: 'session-token' });

        const account = await getOidcAccountInfo(config, getToken, getSession);

        expect(account.pk).toBe(17);
        expect(account.username).toBe('alice');
        expect(account.access_token).toBe('access-token');
        expect(account.oidc_config).toBe(config);
    });

    it('does not create a MapStore account without the GeoNode browser session', async() => {
        const account = await getOidcAccountInfo(
            { enabled: true },
            async() => ({ access_token: 'access-token' }),
            async() => { throw new Error('session expired'); }
        );

        expect(account).toBe(null);
    });
});
