const GTextEncoder = new TextEncoder('utf-8');
const GTextDecoder = new TextDecoder("utf-8");
const DataUtil = {
    bytesToBase64: function (buffer) {
        let b64 = btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
        return b64;
    },
    base64ToBytes: function (b64) {
        let binStr = atob(b64);
        let rawLength = binStr.length;
        let array = new Uint8Array(new ArrayBuffer(rawLength));
        for (let i = 0; i < rawLength; i++) {
            array[i] = binStr.charCodeAt(i);
        }
        return array;
    },

    strToBytes: function (str) {
        let bytes = GTextEncoder.encode(str);
        return bytes;
    },
    bytesToStr: function (buffer) {
        let str = GTextDecoder.decode(buffer);
        return str;
    },

    bigIntToBytes: function (bn) {
        if (bn != null && bn !== undefined) {
            let hex = bn.toString(16);
            if (hex.length % 2) {
                hex = '0' + hex;
            }
            let len = hex.length / 2;
            let u8 = new Uint8Array(len);
            let i = 0;
            let j = 0;
            while (i < len) {
                u8[i] = parseInt(hex.slice(j, j + 2), 16);
                i += 1;
                j += 2;
            }
            return u8;
        }
    },
    bytesToBigInt: function (buf) {
        let hex = [];
        let u8 = Uint8Array.from(buf);
        u8.forEach(function (i) {
            let h = i.toString(16);
            if (h.length % 2) {
                h = '0' + h;
            }
            hex.push(h);
        });
        return bigInt(hex.join(''), 16);
    },
    unescape: function (str) {
        return (str + '==='.slice((str.length + 3) % 4))
            .replace(/-/g, '+')
            .replace(/_/g, '/')
    },
    escape: function (str) {
        return str.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    },
    bytesToBase64Url: function (buffer) {
        return this.escape(this.bytesToBase64(buffer));
    },
    base64UrlToBytes: function (b64) {
        return this.base64ToBytes(this.unescape(b64));
    }
};
const FormUtil = {
    postJson: function (url, data, success, error) {
        $.ajax({
            url: url,
            crossDomain: false,
            dataType: "json",
            headers: {
                'accept': 'application/json',
                'Content-Type': 'application/json'
            },
            method: "POST",
            scriptCharset: "utf-8",
            processData: false,
            data: JSON.stringify(data),
            success: success,
            error: error,
        });
    }
};