package com.et.hackathon.firewall.service;

import com.et.hackathon.firewall.dto.DetectionFinding;
import com.et.hackathon.firewall.dto.SourceType;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class ContentSanitizer {
    private final List<Pattern> suspiciousLinePatterns = List.of(
            Pattern.compile("(?i).*(ignore|disregard|forget|override)\\s+(?:(?:all|any|the|previous|prior|above|system|developer|safety)\\s+){0,3}(instructions|rules|policies|messages).*"),
            Pattern.compile("(?i).*(reveal|show|dump|print).*\\b(system prompt|developer message|hidden prompt|private context|api key|password|token)\\b.*"),
            Pattern.compile("(?i).*(you are now|act as|pretend to be).*"),
            Pattern.compile("(?i).*(execute|invoke|call).*(shell|terminal|browser|database|filesystem).*"),
            Pattern.compile("(?i).*(system|developer|security policy|memory update)\\s*[:=-].*"),
            Pattern.compile("(?i).*follow these instructions.*")
    );

    public String sanitize(String content) {
        if (content == null || content.isBlank()) return content;
        List<String> kept = new ArrayList<>();
        for (String line : content.split("\\R", -1)) {
            boolean suspicious = suspiciousLinePatterns.stream().anyMatch(p -> p.matcher(line).matches());
            if (suspicious) {
                kept.add("[UNTRUSTED_INSTRUCTION_REMOVED]");
            } else {
                kept.add(line);
            }
        }
        return String.join(System.lineSeparator(), kept);
    }

    public String sanitizeUntrustedDocument(String content, List<DetectionFinding> findings) {
        String defanged = content == null ? "" : content;
        if (findings != null) {
            for (DetectionFinding finding : findings) {
                String evidence = finding.getEvidence();
                if (evidence != null && !evidence.isBlank()) {
                    defanged = Pattern.compile(Pattern.quote(evidence), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE)
                            .matcher(defanged)
                            .replaceAll("[FLAGGED_UNTRUSTED_INSTRUCTION]");
                }
            }
        }
        defanged = defanged.replace("<", "&lt;").replace(">", "&gt;");
        return "<untrusted_document>\n" + defanged + "\n</untrusted_document>";
    }

    public boolean isUntrustedDocument(SourceType sourceType) {
        if (sourceType == null) return false;
        return switch (sourceType) {
            case WEB_PAGE, PDF, EMAIL, MARKDOWN, HTML, WORD_DOCUMENT, OCR_TEXT, SOURCE_CODE, IMAGE,
                    API_RESPONSE -> true;
            default -> false;
        };
    }
}
