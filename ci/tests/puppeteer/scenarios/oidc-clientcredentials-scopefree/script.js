const assert = require('assert');
const cas = require('../../cas.js');

(async () => {

    let params = "grant_type=client_credentials&";
    params += "scope=openid";

    let url = `https://localhost:8443/cas/oidc/token?${params}`;
    await cas.log(`Calling ${url}`);

    await cas.doPost(url, "", {
        'Content-Type': "application/json",
        'Authorization': 'Basic ' + btoa('client' + ':' + 'secret')
    }, async res => {

        await cas.log(res.data);
        assert(res.data.access_token !== null);

        await cas.log("Decoding JWT access token...");
        let decoded = await cas.decodeJwt(res.data.id_token);

        assert(res.data.id_token !== null);
        assert(res.data.refresh_token !== null);
        assert(res.data.token_type !== null);
        assert(res.data.scope !== null);
        assert(decoded.sub !== null);
        assert(decoded.cn !== null);
        assert(decoded.name !== null);
        assert(decoded["preferred_username"] !== null);
        assert(decoded["given-name"] !== null)
    }, error => {
        throw `Operation failed: ${error}`;
    });
})();
