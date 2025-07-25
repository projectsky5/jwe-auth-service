package com.projectsky.jweauthservice.config.props;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt.keys")
@Data
public class KeysProperties {

    private final Hmac hmac = new Hmac();
    private final Encrypt encrypt = new Encrypt();

    @Data
    public static class Hmac{
        private String secret; // для JWS подписи
    }

    @Data
    public static class Encrypt{
        private String privateKey; // для JWE расшифровки
        private String publicKey; // для JWE шифрования
    }
}
