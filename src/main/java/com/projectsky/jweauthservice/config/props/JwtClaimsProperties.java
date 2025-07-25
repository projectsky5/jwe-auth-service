package com.projectsky.jweauthservice.config.props;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "security.jwt.claims")
@Data
public class JwtClaimsProperties {
    private String issuer;
    private String audience;
    private List<String> requiredClaims = new ArrayList<>();
}
