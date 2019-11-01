const Authenticator = {
    loginByUnamePasswd: function (uname, passwd, callback) {
        let data = {
            username: uname,
            password: passwd
        };
        let success = function (data) {
            let result = (data.result === "0");
            alert("Login result:" + result);
            callback(result);
        };
        let error = function (err) {
            alert(err);
            console.log("Error:" + err);
            callback(false);
        };
        FormUtil.postJson("login", data, success, error);
    },
    loginByECDH: function (uname, passwd, callback) {
        let promise = new Promise(function (resolve, reject) {
            resolve(passwd)
        });
        promise.then(async function (val) {
            let data = DataUtil.strToBytes(val);
            const hashPasswd = await HCrypto.hash("SHA-256", data);
            console.log("Hashed passwd:" + hashPasswd);
            let sqrHashedPwd = DataUtil.bytesToBigInt(DataUtil.base64ToBytes(hashPasswd)).pow(2);
            console.log("Num passwd:" + sqrHashedPwd);
            const dhParams = {
                name: "ECDH",
                namedCurve: "P-256"
            };
            const keyPair = await HCrypto.generateKey(dhParams, ["deriveKey", "deriveBits"]);
            let priKey = keyPair.privateKey;
            let pubKey = keyPair.publicKey;
            let priKeyData = await HCrypto.exportKey("jwk", priKey);
            let pubKeyData = await HCrypto.exportKey("jwk", pubKey);
            console.log("Pri Key:" + JSON.stringify(priKeyData));
            console.log("Pub Key:" + JSON.stringify(pubKeyData));
            let commonSecretKey = await HCrypto.deriveKey({
                    name: "ECDH",
                    namedCurve: "P-256",
                    public: pubKey
                },
                priKey,{
                    name: "AES-CTR",
                    length: 256
                }, ["encrypt", "decrypt"]);
            let keyData = await HCrypto.exportKey("jwk", commonSecretKey);
            console.log("Common Key:" + JSON.stringify(keyData));
        }).catch(function (err) {
            alert(err);
        });
    },
    encryptByPasswd: async function(passwd, salt, iterations, data){
        let passwdBin = DataUtil.strToBytes(passwd);
        let key = await HCrypto.importKey("raw",
            passwdBin,
            {name: "PBKDF2"},
            ['deriveKey', 'deriveBits']);
        let webKey = await HCrypto.deriveKey({
                name: "PBKDF2",
                salt: salt,
                iterations: iterations,
                hash: "SHA-256"
            }, key,
            {name: "AES-KW", length: 128},
            ["wrapKey", "unwrapKey"]);
        // let sKey = await HCrypto.exportKey("raw", webKey);
        // console.log("Secret key:" + DataUtil.bytesToBase64Url(sKey));
        let sKey = await HCrypto.exportKey("jwk", webKey);
        console.log("Secret key:" + sKey);
        let param = {
            keyEncryptionAlg: "A128KW",
            contentEncryptionAlg: "A128CBC-HS256",
            algName: "AES-KW",
            // kwk: {"kty": "oct", "k": DataUtil.bytesToBase64Url(sKey)}
            kek: sKey
        };
        let dataEnc = await HCrypto.encryptJwt(param, data);
        // console.log("Username enc:" + unameEnc);
        // let unameDec = await HCrypto.decryptJwt(param, unameEnc);
        // console.log("Username dec:" + unameDec);
        return dataEnc;
    },
    loginByPBKDF2: function (uname, passwd, callback) {
        let salt = DataUtil.strToBytes("0000");
        let iterations = 10240;
        let promise = new Promise(function (resolve, reject) {
            let data = {
                username: uname,
                password: passwd,
                data: ""
            };
            resolve(data)
        });
        promise.then(function (data) {
            // call submit username and get salts: salt for passwd and salt for username
            // encrypt username and username salt
            // send to server
        }).then(async function (val) {
            let rs = await this.encryptByPasswd(val.password, salt, iterations, val.data);
            return rs;
        }).catch(function (err) {
            console.log(err);
        });
    }
}