package com.et.hackathon.firewall.service;

import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

@Service
public class ContentNormalizer {
    public Normalized normalize(String input) {
        String raw = input == null ? "" : input;
        Set<String> decodedIndicators = new LinkedHashSet<>();
        StringBuilder combined = new StringBuilder(raw);

        String urlDecoded = safeUrlDecode(raw);
        if (!urlDecoded.equals(raw)) {
            combined.append("\n[URL_DECODED]\n").append(urlDecoded);
            decodedIndicators.add("URL-decoded view generated");
        }

        for (String token : raw.split("\\s+")) {
            String candidate = token.replaceAll("[^A-Za-z0-9+/=_-]", "");
            if (candidate.length() >= 24 && candidate.length() % 4 == 0) {
                try {
                    String decoded = new String(Base64.getDecoder().decode(candidate), StandardCharsets.UTF_8);
                    if (decoded.chars().allMatch(c -> c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127))) {
                        combined.append("\n[BASE64_DECODED]\n").append(decoded);
                        decodedIndicators.add("Base64-like payload decoded for inspection");
                    }
                } catch (IllegalArgumentException ignored) {
                    // Not valid Base64.
                }
            }
        }
        return new Normalized(raw, combined.toString(), decodedIndicators.stream().toList());
    }

    private String safeUrlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return value;
        }
    }

    public record Normalized(String raw, String searchable, java.util.List<String> decodedIndicators) {}
}
