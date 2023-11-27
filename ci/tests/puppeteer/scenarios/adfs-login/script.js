const puppeteer = require('puppeteer');
const assert = require('assert');
const cas = require('../../cas.js');

(async () => {
    let body = {"configuredLevel": "WARN"};
    await ["org.apereo.cas", "org.apereo.cas.web", "org.apereo.cas.web.flow"].forEach(p =>
        cas.doRequest(`https://localhost:8443/cas/actuator/loggers/${p}`, "POST",
            {'Content-Type': 'application/json'}, 204, JSON.stringify(body, undefined, 2)));
    const service = "https://apereo.github.io";
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);
    await cas.log(`Navigating to ${service}`);
    await cas.goto(page, `https://localhost:8443/cas/login?service=${service}`);
    await page.waitForTimeout(2000);
    await cas.click(page, "div .idp span");
    await page.waitForTimeout(4000);
    await cas.screenshot(page);
    await cas.type(page, "#userNameInput", process.env.ADFS_USERNAME, true);
    await cas.type(page, "#passwordInput", process.env.ADFS_PASSWORD, true);
    await page.waitForTimeout(1000);
    await cas.screenshot(page);
    await cas.submitForm(page, "#loginForm");
    await page.waitForTimeout(4000);
    await cas.screenshot(page);
    let ticket = await cas.assertTicketParameter(page);
    await cas.gotoLogin(page);
    await cas.assertCookie(page);
    await page.waitForTimeout(3000);
    body = await cas.doRequest(`https://localhost:8443/cas/p3/serviceValidate?service=${service}&ticket=${ticket}&format=JSON`);
    await cas.log(body);
    let json = JSON.parse(body);
    let authenticationSuccess = json.serviceResponse.authenticationSuccess;
    assert(authenticationSuccess.user.includes("casuser@apereo.org"));
    assert(authenticationSuccess.attributes.firstname != null);
    assert(authenticationSuccess.attributes.lastname != null);
    assert(authenticationSuccess.attributes.uid != null);
    assert(authenticationSuccess.attributes.upn != null);
    assert(authenticationSuccess.attributes.username != null);
    assert(authenticationSuccess.attributes.surname != null);
    assert(authenticationSuccess.attributes.email != null);
    await browser.close();
})();
