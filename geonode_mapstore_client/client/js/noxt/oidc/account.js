/**
 * GeoNoXT OIDC account adapter. MapStore still uses GeoNode's browser session
 * for API calls; this only attaches the provider token for the refresh manager.
 */
export const getOidcAccountInfo = async(oidcConfig, getOidcAccessToken, getSessionUserInfo) => {
    let token = await getOidcAccessToken(oidcConfig);
    const sessionInfo = await getSessionUserInfo().catch(() => null);
    if (!sessionInfo) return null;

    token = token || await getOidcAccessToken(oidcConfig, { allowSilentAuthorization: true });
    const { preferred_username: username, sub } = sessionInfo;
    const pk = Number.isNaN(Number(sub)) ? sub : Number(sub);
    const accountInfo = {
        ...sessionInfo,
        pk,
        username,
        // TODO: remove when the href is provided by the server
        hrefProfile: `/people/profile/${username}/`
    };
    delete accountInfo.access_token;
    if (token) {
        accountInfo.access_token = token.access_token;
        accountInfo.oidc_config = oidcConfig;
    }
    return accountInfo;
};
