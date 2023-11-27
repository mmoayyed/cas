const puppeteer = require('puppeteer');
const cas = require('../../cas.js');

(async () => {
    const browser = await puppeteer.launch(cas.browserOptions());
    const page = await cas.newPage(browser);
    await cas.gotoLogin(page);

    await page.waitForTimeout(1000);
    await cas.assertVisibility(page, '#webauthnLoginPanel div h2#status');
    await cas.assertTextContent(page, "#webauthnLoginPanel div h2#status","Login with FIDO2-enabled Device");
    await browser.close();
})();
