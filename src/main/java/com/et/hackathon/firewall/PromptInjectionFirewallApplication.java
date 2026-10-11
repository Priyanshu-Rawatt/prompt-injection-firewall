package com.et.hackathon.firewall;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PromptInjectionFirewallApplication {
    public static void main(String[] args) {
        SpringApplication.run(PromptInjectionFirewallApplication.class, args);
    }
}
