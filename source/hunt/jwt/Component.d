module hunt.jwt.Component;

import hunt.jwt.Base64Codec;

/**
 * 
 */
class Component {
    abstract @property string json();

    @property string base64() {
        string data = this.json();
        return urlsafeB64Encode(data);
    }
}

