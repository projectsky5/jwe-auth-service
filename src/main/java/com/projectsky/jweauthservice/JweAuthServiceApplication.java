package com.projectsky.jweauthservice;

import com.projectsky.jweauthservice.config.props.JwtClaimsProperties;
import com.projectsky.jweauthservice.config.props.KeysProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({KeysProperties.class, JwtClaimsProperties.class})
public class JweAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(JweAuthServiceApplication.class, args);
    }

}
