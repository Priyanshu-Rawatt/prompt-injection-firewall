package com.et.hackathon.firewall.service.detector;

import com.et.hackathon.firewall.dto.Decision;
import com.et.hackathon.firewall.dto.SourceType;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class HardNegativeEvaluationTest {
    private final RuleBasedDetector detector = new RuleBasedDetector();
    private final List<Pattern> legacySignatures = List.of(
            Pattern.compile("(?i)(ignore|disregard|forget|override)\\s+(?:(?:all|any|the|previous|prior|above|system|developer|safety)\\s+){0,3}(instructions|rules|policies|messages)"),
            Pattern.compile("(?i)(you are now|act as|pretend to be|switch to|assume the role of)\\s+[^.\\n]{0,100}"),
            Pattern.compile("(?i)(reveal|show|print|leak|dump|disclose|expose)\\s+(the|your|all)?\\s*(system prompt|developer message|hidden prompt|private context|secret|confidential|internal instructions)"),
            Pattern.compile("(?i)(call|invoke|execute|run|use)\\s+(the\\s+)?(browser|shell|terminal|database|admin|filesystem|email|payment|http)\\s*(tool|function|command|api)?"),
            Pattern.compile("(?i)(send|give|provide|paste|reveal|extract|show)\\s+(me|us|to me)?\\s*(your|the)?\\s*(password|passcode|otp|one[- ]time code|api key|access token|bearer token|secret key|credential)"),
            Pattern.compile("(?i)(system message|developer message|trusted source|security policy|memory update|authoritative instruction|highest priority)\\s*[:=-]"),
            Pattern.compile("(?is)(step\\s*1.{0,400}step\\s*2|first.{0,250}then.{0,250}(ignore|bypass|reveal|execute)|phase\\s*1.{0,400}phase\\s*2)"),
            Pattern.compile("(?i)(base64|b64|url[- ]encoded|hex encoded|decode this|percent[- ]encoded)")
    );

    @Test
    void separatesUseFromMentionOnHardNegativeCases() throws Exception {
        var stream = getClass().getResourceAsStream("/evaluation/hard-negatives.tsv");
        assertThat(stream).as("hard-negative dataset").isNotNull();
        int benignCases = 0;
        int benignFalsePositives = 0;
        int attackCases = 0;
        int attackTruePositives = 0;
        int baselineFalsePositives = 0;
        int baselineTruePositives = 0;
        int baselineFalseNegatives = 0;
        int currentFalsePositives = 0;
        int currentTruePositives = 0;
        int currentFalseNegatives = 0;

        try (var reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            assertThat(reader.readLine()).isEqualTo("id\tsource\texpected\ttext");
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split("\t", 4);
                assertThat(fields).as("case row: " + line).hasSize(4);
                var result = detector.analyze(fields[3], fields[3], SourceType.valueOf(fields[1]));
                boolean blocked = result.score() >= 0.78;
                boolean currentFlagged = result.score() >= 0.48;
                boolean baselineFlagged = legacyFlagged(fields[3], SourceType.valueOf(fields[1]));
                if (fields[2].equals("BENIGN")) {
                    benignCases++;
                    if (result.score() >= 0.48) benignFalsePositives++;
                    if (baselineFlagged) baselineFalsePositives++;
                    if (currentFlagged) currentFalsePositives++;
                    assertThat(result.score()).as(fields[0] + " benign score").isLessThan(0.48);
                } else {
                    attackCases++;
                    if (blocked) attackTruePositives++;
                    if (baselineFlagged) baselineTruePositives++;
                    else baselineFalseNegatives++;
                    if (currentFlagged) currentTruePositives++;
                    else currentFalseNegatives++;
                    assertThat(blocked).as(fields[0] + " attack decision (score=" + result.score() + ")").isTrue();
                }
            }
        }

        double falsePositiveRate = (double) benignFalsePositives / benignCases;
        double attackRecall = (double) attackTruePositives / attackCases;
        double baselineFalsePositiveRate = (double) baselineFalsePositives / benignCases;
        double baselinePrecision = ratio(baselineTruePositives,
                baselineTruePositives + baselineFalsePositives);
        double baselineRecall = ratio(baselineTruePositives,
                baselineTruePositives + baselineFalseNegatives);
        double currentPrecision = ratio(currentTruePositives, currentTruePositives + currentFalsePositives);
        System.out.printf("Legacy keyword baseline: precision=%.3f recall=%.3f benign FPR=%.3f (%d/%d)%n",
                baselinePrecision, baselineRecall, baselineFalsePositiveRate, baselineFalsePositives, benignCases);
        System.out.printf("Context-weighted detector: precision=%.3f recall=%.3f benign FPR=%.3f (%d/%d)%n",
                currentPrecision, attackRecall, falsePositiveRate, benignFalsePositives, benignCases);
        assertThat(benignFalsePositives).isZero();
        assertThat(attackTruePositives).isEqualTo(attackCases);
        assertThat(falsePositiveRate).isLessThan(baselineFalsePositiveRate);
        assertThat(attackRecall).isGreaterThanOrEqualTo(baselineRecall);
    }

    private boolean legacyFlagged(String text, SourceType source) {
        if (legacySignatures.stream().anyMatch(pattern -> pattern.matcher(text).find())) return true;
        if (source == SourceType.USER_MESSAGE) return false;
        String lower = text.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("ignore previous") || lower.contains("ignore all prior")
                || lower.contains("reveal the system prompt") || lower.contains("reveal hidden instructions")
                || lower.contains("provide the api key") || lower.contains("send the password")
                || lower.contains("execute this command") || lower.contains("act as the system")
                || lower.contains("developer message") || lower.contains("assistant:")
                || lower.contains("system:") || lower.contains("developer:")
                || lower.contains("do not tell the user") || lower.contains("when the agent")
                || lower.contains("follow these instructions");
    }

    private double ratio(int numerator, int denominator) {
        return denominator == 0 ? 0 : (double) numerator / denominator;
    }
}
