package com.habeebcycle.demo.jwt;

import com.google.common.net.HttpHeaders;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("application.jwt")
public class JwtConfig {

    private String secret;
    private String tokenPrefix;
    private Integer tokenExpirationDays;

    public JwtConfig() {
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpirationDays() {
        return tokenExpirationDays;
    }

    public void setTokenExpirationDays(Integer tokenExpirationDays) {
        this.tokenExpirationDays = tokenExpirationDays;
    }

    public String getAuthorizationHeader(){
        return HttpHeaders.AUTHORIZATION;
    }
}
