package com.et.hackathon.firewall.service.detector;

import com.et.hackathon.firewall.dto.AttackType;
import com.et.hackathon.firewall.dto.SourceType;
import com.et.hackathon.firewall.service.ContentNormalizer;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class FirewallEvaluationDatasetTest {
    private final RuleBasedDetector detector = new RuleBasedDetector();
    private final ContentNormalizer normalizer = new ContentNormalizer();

    @Test
    void runsLabeledAttackAndBenignRegressionCorpus() throws Exception {
        var stream = getClass().getResourceAsStream("/evaluation/dataset.csv");
        assertThat(stream).as("evaluation dataset").isNotNull();
        Map<AttackType, Counts> counts = new EnumMap<>(AttackType.class);
        Map<AttackType, Integer> caseCounts = new EnumMap<>(AttackType.class);
        int benignCases = 0;
        int benignFalsePositives = 0;
        int cases = 0;

        try (var reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            assertThat(reader.readLine()).isEqualTo("id,source_type,text,expected_attack,expected_decision");
            String line;
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split(",", 5);
                assertThat(fields).as("CSV row: " + line).hasSize(5);
                String id = fields[0].trim();
                SourceType source = SourceType.valueOf(fields[1].trim());
                String content = fields[2].trim();
                String expected = fields[3].trim();
                String expectedDecision = fields[4].trim();
                Set<AttackType> expectedTypes = expected.equals("NONE") ? Set.of()
                        : Arrays.stream(expected.split("\\|")).map(String::trim).map(AttackType::valueOf).collect(Collectors.toSet());
                var normalized = normalizer.normalize(content);
                var result = detector.analyze(normalized.raw(), normalized.searchable(), source);
                var found = result.findings().stream()
                        .map(finding -> finding.getAttackType())
                        .collect(Collectors.toSet());
                String actualDecision = found.isEmpty() ? "ALLOW" : result.score() >= 0.78 ? "BLOCK"
                        : result.score() >= 0.48 ? "SANITIZE" : "REVIEW";
                assertThat(actualDecision).as(id + " policy decision").isEqualTo(expectedDecision);

                if (expected.equals("NONE")) {
                    benignCases++;
                    if (!found.isEmpty()) benignFalsePositives++;
                    found.forEach(predicted ->
                            counts.computeIfAbsent(predicted, ignored -> new Counts()).falsePositives++);
                    assertThat(found).as(id).isEmpty();
                } else {
                    if (!expectedTypes.containsAll(found)) {
                        System.out.printf("%s unexpected findings: expected=%s actual=%s%n", id, expectedTypes, found);
                    }
                    expectedTypes.forEach(expectedType -> {
                        caseCounts.merge(expectedType, 1, Integer::sum);
                        Counts countsForType = counts.computeIfAbsent(expectedType, ignored -> new Counts());
                        if (found.contains(expectedType)) countsForType.truePositives++;
                        else countsForType.falseNegatives++;
                    });
                    for (AttackType predicted : found) {
                        if (!expectedTypes.contains(predicted)) {
                            counts.computeIfAbsent(predicted, ignored -> new Counts()).falsePositives++;
                        }
                    }
                    assertThat(found).as(id + " expected " + expectedTypes + " but found " + found)
                            .containsAll(expectedTypes);
                }
                cases++;
            }
        }

        assertThat(cases).isEqualTo(120);
        assertThat(benignCases).isEqualTo(30);
        assertThat(benignFalsePositives).isZero();
        assertThat(caseCounts).containsOnlyKeys(AttackType.values());
        assertThat(caseCounts.values()).allSatisfy(count -> assertThat(count).isGreaterThanOrEqualTo(10));
        counts.forEach((type, value) -> {
            double precision = (double) value.truePositives
                    / Math.max(1, value.truePositives + value.falsePositives);
            double recall = (double) value.truePositives
                    / Math.max(1, value.truePositives + value.falseNegatives);
            System.out.printf("%s precision=%.3f recall=%.3f%n", type, precision, recall);
        });
        System.out.printf("benign false-positive rate=%.3f (%d/%d)%n",
                (double) benignFalsePositives / benignCases, benignFalsePositives, benignCases);
    }

    private static final class Counts {
        private int truePositives;
        private int falsePositives;
        private int falseNegatives;
    }
}
