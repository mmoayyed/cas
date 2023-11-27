const puppeteer = require('puppeteer');
const cas = require('../../cas.js');
const assert = require('assert');

async function fetchRefreshToken(page, clientId, redirectUrl) {
    let url = `https://localhost:8443/cas/oidc/authorize?response_type=code&client_id=${clientId}&scope=openid%20offline_access&prompt=login&redirect_uri=${redirectUrl}&nonce=3d3a7457f9ad3&state=1735fd6c43c14`;

    await cas.log(`Navigating to ${url}`);
    await cas.goto(page, url);
    await page.waitForTimeout(1000);
    await cas.loginWith(page);
    await page.waitForTimeout(1000);

    if (await cas.isVisible(page, "#allow")) {
        await cas.click(page, "#allow");
        await page.waitForNavigation();
    }

    let code = await cas.assertParameter(page, "code");
    await cas.log(`OAuth code ${code}`);

    let accessTokenParams = `client_id=${clientId}&`;
    accessTokenParams += "client_secret=secret&";
    accessTokenParams += "grant_type=authorization_code&";
    accessTokenParams += `redirect_uri=${redirectUrl}`;

    let accessToken = null;
    let refreshToken = null;

    let accessTokenUrl = `https://localhost:8443/cas/oidc/token?${accessTokenParams}&code=${code}`;
    await cas.doPost(accessTokenUrl, "", {'Content-Type': "application/json"},
        res => {
            
            assert(res.data.access_token !== null);
            assert(res.data.refresh_token !== null);

            accessToken = res.data.access_token;
            refreshToken = res.data.refresh_token;

            cas.log(`Received access token ${accessToken}`);
            cas.log(`Received refresh token ${refreshToken}`);
        },
        () => {
            throw `Operation failed to obtain access token: ${error}`;
        });

    assert(accessToken != null, "Access Token cannot be null");
    assert(refreshToken != null, "Refresh Token cannot be null");
    return refreshToken;
}

async function exchangeToken(refreshToken, clientId, successHandler, errorHandler) {
    let accessTokenParams = "scope=openid%offline_access";
    accessTokenParams += `&grant_type=refresh_token&refresh_token=${refreshToken}`;

    let accessTokenUrl = `https://localhost:8443/cas/oidc/token?${accessTokenParams}`;
    cas.log(`Calling endpoint: ${accessTokenUrl}`);

    let value = `${clientId}:secret`;
    let buff = Buffer.alloc(value.length, value);
    let authzHeader = `Basic ${buff.toString('base64')}`;
    await cas.log(`Authorization header: ${authzHeader}`);

    await cas.doPost(accessTokenUrl, "", {
        'Content-Type': "application/json",
        'Authorization': authzHeader
    }, successHandler, errorHandler);
}

(async () => {
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);

    await cas.logg("Fetching first refresh token");
    const redirectUrl1 = "https://github.com/apereo/cas";
    let refreshToken1 = await fetchRefreshToken(page, "client", redirectUrl1);

    await cas.log("**********************************************");
    
    await cas.logg("Fetching second refresh token");
    const redirectUrl2 = "https://apereo.github.io";
    let refreshToken2 = await fetchRefreshToken(page, "client2", redirectUrl2);

    await cas.logg(`Refresh Token 1: ${refreshToken1}`);
    await cas.logg(`Refresh Token 2: ${refreshToken2}`);

    await exchangeToken(refreshToken2, "client",
        res => {
            throw `Operation should fail but instead produced: ${res.data}`;
        }, error => {
            cas.log(`Status: ${error.response.status}`);
            assert(error.response.status === 400);
            cas.log(error.response.data);
            assert(error.response.data.error === "invalid_grant");
        });

    await exchangeToken(refreshToken1, "client2",
        res => {
            throw `Operation should fail but instead produced: ${res.data}`;
        }, error => {
            cas.log(`Status: ${error.response.status}`);
            assert(error.response.status === 400);
            cas.log(error.response.data);
            assert(error.response.data.error === "invalid_grant");
        });

    await exchangeToken(refreshToken1, "client",
        res => {
            cas.log(res.data);
            assert(res.status === 200);
        }, error => {
            throw `Operation should not fail but instead produced: ${error}`;
        });

    cas.log("Let's wait 5 seconds for the TGT to expire, RTs should be still alive");
    await page.waitForTimeout(5000);

    await exchangeToken(refreshToken1, "client",
        res => {
            cas.log(res.data);
            assert(res.status === 200);
        }, error => {
            throw `Operation should not fail`;
        });

    await exchangeToken(refreshToken2, "client2",
        res => {
            cas.log(res.data);
            assert(res.status === 200);
        }, error => {
            throw `Operation should not fail`;
        });

    await browser.close();
})();
