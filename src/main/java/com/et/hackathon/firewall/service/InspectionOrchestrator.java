package com.et.hackathon.firewall.service;

import com.et.hackathon.firewall.config.FirewallProperties;
import com.et.hackathon.firewall.dto.*;
import com.et.hackathon.firewall.entity.InspectionEvent;
import com.et.hackathon.firewall.repository.InspectionEventRepository;
import com.et.hackathon.firewall.service.detector.RuleBasedDetector;
import com.et.hackathon.firewall.service.llm.LlmRiskAnalyzerRouter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
public class InspectionOrchestrator {
    private static final Logger log = LoggerFactory.getLogger(InspectionOrchestrator.class);

    private final FirewallProperties properties;
    private final ContentNormalizer normalizer;
    private final RuleBasedDetector ruleDetector;
    private final LlmRiskAnalyzerRouter llmRouter;
    private final ContentSanitizer sanitizer;
    private final InspectionEventRepository auditRepository;

    public InspectionOrchestrator(FirewallProperties properties,
                                   ContentNormalizer normalizer,
                                   RuleBasedDetector ruleDetector,
                                   LlmRiskAnalyzerRouter llmRouter,
                                   ContentSanitizer sanitizer,
                                   InspectionEventRepository auditRepository) {
        this.properties = properties;
        this.normalizer = normalizer;
        this.ruleDetector = ruleDetector;
        this.llmRouter = llmRouter;
        this.sanitizer = sanitizer;
        this.auditRepository = auditRepository;
    }

    public InspectionResponse inspect(String content, SourceType sourceType) {
        return inspect(content, sourceType, List.of());
    }

    public InspectionResponse inspect(String content, SourceType sourceType, List<String> extractionDetails) {
        String requestId = UUID.randomUUID().toString();
        SourceType actualSource = sourceType == null ? SourceType.UNKNOWN : sourceType;
        List<String> actualExtractionDetails = extractionDetails == null ? List.of() : List.copyOf(extractionDetails);
        List<String> trace = new ArrayList<>();
        trace.add("01_ACCEPT: content received as UNTRUSTED DATA");
        trace.addAll(actualExtractionDetails.stream().map(detail -> "EXTRACTION: " + detail).toList());

        String safeInput = content == null ? "" : content;
        if (safeInput.length() > properties.maxContentLength()) {
            trace.add("02_REJECT_SIZE: content exceeds maximum inspection size");
            String hash = sha256(safeInput);
            auditRepository.save(InspectionEvent.of(actualSource.name(), Decision.BLOCK.name(), 1.0, "CRITICAL", hash, false));
            return new InspectionResponse(requestId, Decision.BLOCK, 1.0, "CRITICAL", actualSource.name(), hash,
                    "[CONTENT_TOO_LARGE_BLOCKED]", false, List.of(), List.of(), trace, actualExtractionDetails);
        }

        ContentNormalizer.Normalized normalized = normalizer.normalize(safeInput);
        trace.add("02_NORMALIZE: URL/Base64 views generated for inspection; no payload executed");

        RuleBasedDetector.DetectionResult rules = ruleDetector.analyze(normalized.raw(), normalized.searchable(), actualSource);
        trace.add("03_RULE_SCAN: deterministic signatures and source-aware heuristics evaluated");

        List<DetectionFinding> findings = new ArrayList<>(rules.findings());
        double score = rules.score();
        boolean llmUsed = false;
        boolean classifierUncertain = false;
        boolean deterministicAttackDetected = !rules.findings().isEmpty();
        boolean definitiveRuleBlock = deterministicAttackDetected
                || score >= properties.blockThreshold() && !sanitizer.isUntrustedDocument(actualSource);
        boolean classifierAvailable = properties.llm().enabled() && llmRouter.isAvailable();

        if (!definitiveRuleBlock && classifierAvailable) {
            String provider = llmRouter.activeProvider();
            long startedAt = System.nanoTime();
            log.info("LLM classifier call started: requestId={}, source={}, provider={}",
                    requestId, actualSource, provider);
            try {
                var llm = llmRouter.analyze(normalized.searchable());
                if (llm != null) {
                    llmUsed = true;
                    String label = Objects.toString(llm.getLabel(), "UNCERTAIN").toUpperCase(Locale.ROOT);
                    log.info("LLM classifier call completed: requestId={}, provider={}, label={}, riskScore={}, durationMs={}",
                            requestId, provider, label, llm.getRiskScore(),
                            (System.nanoTime() - startedAt) / 1_000_000);
                    if ("ATTACK".equals(label)) {
                        score = Math.max(score, Math.max(properties.blockThreshold(),
                                clamp(llm.getRiskScore())));
                        for (String attack : llm.getAttackTypes() == null ? List.<String>of() : llm.getAttackTypes()) {
                            try {
                                AttackType type = AttackType.valueOf(attack);
                                findings.add(new DetectionFinding(type, clamp(Math.max(llm.getRiskScore(), 0.80)),
                                        "LLM intent classification", "LLM:" + llmRouter.activeProvider(),
                                        llm.getExplanation()));
                            } catch (IllegalArgumentException ignored) {
                                // Ignore unsupported model labels.
                            }
                        }
                        trace.add("04_LLM_ADJUDICATE: content classified as ATTACK");
                    } else if ("DISCUSSION".equals(label) || "BENIGN".equals(label)) {
                        findings.clear();
                        score = 0.0;
                        trace.add("04_LLM_ADJUDICATE: content classified as " + label);
                    } else {
                        log.warn("LLM classifier returned no verdict: requestId={}, provider={}, durationMs={}",
                                requestId, provider, (System.nanoTime() - startedAt) / 1_000_000);
                        classifierUncertain = true;
                        score = Math.max(score, properties.reviewThreshold());
                        trace.add("04_LLM_ADJUDICATE: uncertain classifier result; REVIEW required");
                    }
                } else {
                    classifierUncertain = true;
                    score = Math.max(score, properties.reviewThreshold());
                    trace.add("04_LLM_ADJUDICATE: classifier returned no result; REVIEW required");
                }
            } catch (Exception ex) {
                log.error("LLM classifier call failed: requestId={}, provider={}, durationMs={}, exceptionType={}",
                        requestId, provider, (System.nanoTime() - startedAt) / 1_000_000,
                        ex.getClass().getSimpleName(), ex);
                classifierUncertain = true;
                score = Math.max(score, properties.reviewThreshold());
                trace.add("04_LLM_ADJUDICATE: provider error; REVIEW required");
            }
        } else if (!definitiveRuleBlock) {
            log.warn("LLM classifier unavailable: requestId={}, enabled={}, configuredProvider={}",
                    requestId, properties.llm().enabled(), properties.llm().provider());
            classifierUncertain = true;
            score = Math.max(score, properties.reviewThreshold());
            trace.add("04_LLM_ADJUDICATE: classifier unavailable; REVIEW required before downstream use");
        } else {
            trace.add("04_LLM_ADJUDICATE: skipped; deterministic findings require BLOCK");
        }

        findings = deduplicate(findings);
        score = clamp(Math.max(score, findings.stream().mapToDouble(DetectionFinding::getConfidence).max().orElse(0.0)));

        Decision decision;
        boolean untrustedDocument = sanitizer.isUntrustedDocument(actualSource);
        String sanitized = untrustedDocument
                ? sanitizer.sanitizeUntrustedDocument(safeInput, findings) : safeInput;
        if (deterministicAttackDetected) {
            decision = Decision.BLOCK;
            sanitized = "[FIREWALL_BLOCKED: deterministic attack findings detected]";
            trace.add("05_POLICY: BLOCK because deterministic rules detected an attack");
        } else if (classifierUncertain) {
            decision = Decision.REVIEW;
            sanitized = untrustedDocument
                    ? sanitizer.sanitizeUntrustedDocument(safeInput, findings)
                    : sanitizer.sanitize(safeInput);
            trace.add("05_POLICY: REVIEW because mandatory classifier validation did not produce a trusted verdict");
        } else if (untrustedDocument && !findings.isEmpty()) {
            decision = Decision.SANITIZE;
            sanitized = sanitizer.sanitizeUntrustedDocument(safeInput, findings);
            trace.add("05_POLICY: SANITIZE untrusted document and defang detected instruction spans");
        } else if (score >= properties.blockThreshold()) {
            decision = Decision.BLOCK;
            sanitized = "[FIREWALL_BLOCKED: malicious or high-risk instructions detected]";
            trace.add("05_POLICY: BLOCK because risk crossed hard threshold");
        } else if (!findings.isEmpty() && score >= properties.reviewThreshold()) {
            decision = Decision.SANITIZE;
            sanitized = sanitizer.sanitize(safeInput);
            trace.add("05_POLICY: SANITIZE suspicious instruction-like content before downstream use");
        } else if (!findings.isEmpty()) {
            decision = Decision.REVIEW;
            sanitized = sanitizer.sanitize(safeInput);
            trace.add("05_POLICY: REVIEW because evidence is ambiguous");
        } else {
            decision = Decision.ALLOW;
            trace.add("05_POLICY: ALLOW because no attack evidence met the review threshold");
        }

        boolean downstreamAllowed = decision == Decision.ALLOW || decision == Decision.SANITIZE;
        trace.add("06_ENFORCEMENT: downstreamCallPermitted=" + downstreamAllowed);
        trace.add("07_AUDIT: hashed request metadata persisted; raw content is not persisted");

        String hash = sha256(safeInput);
        String level = score >= 0.90 ? "CRITICAL" : score >= 0.78 ? "HIGH" : score >= 0.48 ? "MEDIUM" : "LOW";
        auditRepository.save(InspectionEvent.of(actualSource.name(), decision.name(), score, level, hash, llmUsed));

        return new InspectionResponse(requestId, decision, score, level, actualSource.name(), hash, sanitized,
                downstreamAllowed, findings, normalized.decodedIndicators(), trace, actualExtractionDetails);
    }

    private List<DetectionFinding> deduplicate(List<DetectionFinding> findings) {
        Map<AttackType, DetectionFinding> best = new EnumMap<>(AttackType.class);
        for (DetectionFinding finding : findings) {
            best.merge(finding.getAttackType(), finding, this::preferMoreSpecificEvidence);
        }
        return best.values().stream().sorted(Comparator.comparing(DetectionFinding::getConfidence).reversed()).toList();
    }

    private DetectionFinding preferMoreSpecificEvidence(DetectionFinding existing, DetectionFinding incoming) {
        double confidence = Math.max(existing.getConfidence(), incoming.getConfidence());
        String evidence = pickEvidence(existing, incoming);
        String source = existing.getConfidence() >= incoming.getConfidence() ? existing.getSource() : incoming.getSource();
        String explanation = existing.getConfidence() >= incoming.getConfidence() ? existing.getExplanation() : incoming.getExplanation();
        return new DetectionFinding(existing.getAttackType(), confidence, evidence, source, explanation);
    }

    private String pickEvidence(DetectionFinding existing, DetectionFinding incoming) {
        String a = existing == null ? null : existing.getEvidence();
        String b = incoming == null ? null : incoming.getEvidence();
        if (a == null || a.isBlank()) return b;
        if (b == null || b.isBlank()) return a;
        if (isGenericEvidence(a) && !isGenericEvidence(b)) return b;
        if (isGenericEvidence(b) && !isGenericEvidence(a)) return a;
        return a.length() >= b.length() ? a : b;
    }

    private boolean isGenericEvidence(String evidence) {
        if (evidence == null) return true;
        String normalized = evidence.trim();
        return normalized.isEmpty()
                || normalized.equalsIgnoreCase("LLM intent classification")
                || normalized.equalsIgnoreCase("Rule-based detection")
                || normalized.equalsIgnoreCase("classifier signal");
    }

    private double clamp(double value) {
        return Math.max(0.0, Math.min(1.0, value));
    }

    private String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
