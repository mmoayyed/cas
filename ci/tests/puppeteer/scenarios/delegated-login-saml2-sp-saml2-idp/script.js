const puppeteer = require('puppeteer');
const assert = require('assert');
const cas = require('../../cas.js');
const path = require('path');

(async () => {
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);

    await cas.gotoLogin(page);
    await page.waitForTimeout(1000);

    await cas.doRequest('https://localhost:8443/cas/sp/metadata', "GET", {}, 200);
    await cas.doRequest('https://localhost:8443/cas/sp/idp/metadata', "GET", {}, 200);

    await cas.goto(page, "http://localhost:9443/simplesaml/module.php/core/authenticate.php?as=default-sp");
    await page.waitForTimeout(1000);

    await cas.assertVisibility(page, 'li #SAML2Client');
    await cas.click(page, "li #SAML2Client");
    await page.waitForTimeout(6000);

    await cas.loginWith(page, "user1", "password");
    await page.waitForTimeout(2000);

    await cas.log("Checking for page URL...");
    await cas.logPage(page);

    await page.waitForSelector('#table_with_attributes', {visible: true});
    await cas.assertInnerTextContains(page, "#content p", "status page of SimpleSAMLphp");
    await cas.assertVisibility(page, "#table_with_attributes");
    let authData = JSON.parse(await cas.innerHTML(page, "details pre"));
    await cas.log(authData);

    await cas.gotoLogin(page);
    await cas.assertCookie(page);
    await cas.removeDirectoryOrFile(path.join(__dirname, '/saml-md'));
    await browser.close();
})();
