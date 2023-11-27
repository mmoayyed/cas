const puppeteer = require('puppeteer');
const cas = require('../../cas.js');
const assert = require("assert");

(async () => {
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);

    const redirectUrl = "https://apereo.github.io";
    const request = "eyJhbGciOiJub25lIn0.eyJzY29wZSI6Im9wZW5pZCIsInJlc3BvbnNlX3R5cGUiOiJj"
        + "b2RlIiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6XC9cL2FwZXJlby5naXRod"
        + "WIuaW8iLCJzdGF0ZSI6InZJTjFiMFk0Q2siLCJub25jZSI6IjFOOW1xUE"
        + "85ZnQiLCJjbGllbnRfaWQiOiJjbGllbnQifQ.";
    const url = `https://localhost:8443/cas/oidc/authorize?request=${request}&scope=openid`;

    await cas.log(`Navigating to ${url}`);
    await cas.goto(page, url);
    await cas.loginWith(page);

    if (await cas.isVisible(page, "#allow")) {
        await cas.click(page, "#allow");
        await page.waitForNavigation();
    }

    let code = await cas.assertParameter(page, "code");
    await cas.log(`OAuth code ${code}`);

    let accessTokenParams = "client_id=client&";
    accessTokenParams += "client_secret=secret&";
    accessTokenParams += "grant_type=authorization_code&";
    accessTokenParams += `redirect_uri=${redirectUrl}`;

    let accessTokenUrl = `https://localhost:8443/cas/oidc/token?${accessTokenParams}&code=${code}`;
    await cas.log(`Calling ${accessTokenUrl}`);

    let accessToken = null;
    await cas.doPost(accessTokenUrl, "", {
        'Content-Type': "application/json"
    }, async res => {
        await cas.log(res.data);
        assert(res.data.access_token !== null);

        accessToken = res.data.access_token;
        await cas.log(`Received access token ${accessToken}`);

        await cas.log("Decoding ID token...");
        let decoded = await cas.decodeJwt(res.data.id_token);
        assert(decoded.sub != null);
        assert(decoded.aud != null);
        assert(decoded.jti != null);
        assert(decoded.sid != null);
        assert(decoded.iss != null);
        assert(decoded.state != null);
        assert(decoded.nonce != null)
    }, error => {
        throw `Operation failed to obtain access token: ${error}`;
    });

    await browser.close();
})();
