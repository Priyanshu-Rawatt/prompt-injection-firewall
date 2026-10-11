package com.et.hackathon.firewall.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
@EnableConfigurationProperties(FirewallProperties.class)
public class AppConfig {
    @org.springframework.context.annotation.Bean
    RestClient restClient(RestClient.Builder builder) {
        return builder.build();
    }
}
