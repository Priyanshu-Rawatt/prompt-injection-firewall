package com.et.hackathon.firewall.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "firewall")
public record FirewallProperties(
        String apiToken,
        int maxContentLength,
        double blockThreshold,
        double reviewThreshold,
        Llm llm,
        Ocr ocr) {

    public record Llm(boolean enabled, String provider, String baseUrl, String model,
                      String geminiApiKey, String geminiModel) {}

    public record Ocr(boolean enabled, String command, int timeoutSeconds, int maxPages,
                      int dpi, long maxPixels) {}
}
