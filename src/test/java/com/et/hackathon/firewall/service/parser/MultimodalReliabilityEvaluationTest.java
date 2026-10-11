package com.et.hackathon.firewall.service.parser;

import com.et.hackathon.firewall.config.FirewallProperties;
import com.et.hackathon.firewall.dto.AttackType;
import com.et.hackathon.firewall.dto.Decision;
import com.et.hackathon.firewall.dto.DetectionFinding;
import com.et.hackathon.firewall.dto.ParsedContent;
import com.et.hackathon.firewall.dto.SourceType;
import com.et.hackathon.firewall.service.detector.RuleBasedDetector;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.poi.util.Units;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFRun;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "firewall.multimodal", matches = "true")
class MultimodalReliabilityEvaluationTest {
    private static final Path SAMPLE_DIRECTORY = Path.of("samples");
    private static final double MINIMUM_DECISION_ACCURACY = 0.95;
    private static final double MINIMUM_ATTACK_RECALL = 0.95;

    @Test
    void evaluatesCuratedMultimodalFilesThroughExtractionAndDetection() throws Exception {
        String ocrCommand = System.getProperty("firewall.ocr.command", "tesseract");
        var ocr = new FirewallProperties.Ocr(true, ocrCommand, 30, 30, 150, 40_000_000);
        var parser = new ContentParserService(new FirewallProperties("test", 120_000, 0.78, 0.48, null, ocr));
        var detector = new RuleBasedDetector();
        List<EvaluationCase> cases = readCases();
        List<EvaluationRecord> records = new ArrayList<>();
        Map<String, ModalityCounts> modalityCounts = new java.util.TreeMap<>();
        Map<AttackType, Counts> attackCounts = new EnumMap<>(AttackType.class);
        int decisionMatches = 0;
        int falsePositiveCases = 0;
        int extractionSuccesses = 0;
        int attackTruePositives = 0;
        int attackFalsePositives = 0;
        int attackFalseNegatives = 0;
        Arrays.stream(AttackType.values()).forEach(type -> attackCounts.put(type, new Counts()));

        for (EvaluationCase evaluationCase : cases) {
            long start = System.nanoTime();
            ParsedContent parsed = parser.parse(toUpload(evaluationCase));
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
            extractionSuccesses++;

            assertThat(parsed.getSourceType())
                    .as(evaluationCase.id() + " source type")
                    .isEqualTo(expectedSourceType(evaluationCase.modality()));
            if (evaluationCase.modality().equals("image")
                    || evaluationCase.modality().equals("scanned-pdf")
                    || evaluationCase.modality().equals("docx-image")
                    || evaluationCase.modality().equals("email-image")) {
                assertThat(parsed.getExtractionDetails())
                        .as(evaluationCase.id() + " extraction provenance")
                        .anyMatch(detail -> detail.contains("OCR")
                                || detail.contains("rendered and OCR-scanned"));
            }

            var detection = detector.analyze(parsed.getText(), parsed.getText(), parsed.getSourceType());
            Set<AttackType> actualAttacks = detection.findings().stream()
                    .map(DetectionFinding::getAttackType)
                    .collect(java.util.stream.Collectors.toCollection(() -> EnumSet.noneOf(AttackType.class)));
            Decision actualDecision = decide(detection.findings(), detection.score());
            boolean expectedBenign = evaluationCase.expectedAttacks().isEmpty();
            Set<AttackType> correctlyFound = EnumSet.noneOf(AttackType.class);
            correctlyFound.addAll(actualAttacks);
            correctlyFound.retainAll(evaluationCase.expectedAttacks());
            evaluationCase.expectedAttacks().forEach(type -> {
                Counts counts = attackCounts.computeIfAbsent(type, ignored -> new Counts());
                if (actualAttacks.contains(type)) counts.truePositives++;
                else counts.falseNegatives++;
            });
            actualAttacks.stream().filter(type -> !evaluationCase.expectedAttacks().contains(type))
                    .forEach(type -> attackCounts.computeIfAbsent(type, ignored -> new Counts()).falsePositives++);

            if (actualDecision == evaluationCase.expectedDecision()) decisionMatches++;
            if (expectedBenign && !actualAttacks.isEmpty()) falsePositiveCases++;
            Set<AttackType> expectedAndFound = EnumSet.noneOf(AttackType.class);
            expectedAndFound.addAll(actualAttacks);
            expectedAndFound.retainAll(evaluationCase.expectedAttacks());
            attackTruePositives += expectedAndFound.size();
            attackFalsePositives += actualAttacks.size() - expectedAndFound.size();
            attackFalseNegatives += evaluationCase.expectedAttacks().size() - expectedAndFound.size();
            modalityCounts.computeIfAbsent(evaluationCase.modality(), ignored -> new ModalityCounts())
                    .record(actualDecision == evaluationCase.expectedDecision(), expectedBenign, actualAttacks, elapsedMillis);
            records.add(new EvaluationRecord(evaluationCase, actualDecision, actualAttacks,
                    parsed.getText().length(), elapsedMillis));
        }

        assertThat(cases).hasSizeGreaterThanOrEqualTo(30);
        assertThat(extractionSuccesses).as("file extraction coverage")
                .isEqualTo(cases.size());
        for (String requiredModality : List.of("image", "scanned-pdf", "docx-image", "email", "email-image")) {
            assertThat(modalityCounts.get(requiredModality))
                    .as(requiredModality + " evaluation cases")
                    .isNotNull();
            assertThat(modalityCounts.get(requiredModality).total)
                    .as(requiredModality + " sample count")
                    .isGreaterThanOrEqualTo(3);
        }
        double decisionAccuracy = (double) decisionMatches / cases.size();
        int expectedAttackCount = attackCounts.values().stream().mapToInt(count -> count.truePositives + count.falseNegatives).sum();
        int detectedExpectedAttackCount = attackCounts.values().stream().mapToInt(count -> count.truePositives).sum();
        double attackRecall = (double) detectedExpectedAttackCount / expectedAttackCount;
        double attackPrecision = (double) attackTruePositives / (attackTruePositives + attackFalsePositives);
        double benignFalsePositiveRate = modalityCounts.values().stream()
                .mapToInt(counts -> counts.falsePositiveBenign).sum()
                / (double) modalityCounts.values().stream().mapToInt(counts -> counts.benign).sum();
        writeReport(records, modalityCounts, attackCounts, decisionAccuracy, attackPrecision, attackRecall,
                benignFalsePositiveRate, falsePositiveCases, extractionSuccesses, cases.size());
        System.out.printf("Multimodal regression corpus: %d/%d extracted, decision accuracy=%.3f, attack precision=%.3f, "
                        + "attack recall=%.3f, benign false-positive rate=%.3f (%d)%n",
                extractionSuccesses, cases.size(), decisionAccuracy, attackPrecision, attackRecall,
                benignFalsePositiveRate, falsePositiveCases);
        modalityCounts.forEach((modality, counts) -> System.out.printf(
                "%s n=%d extracted=%d accuracy=%.3f false-positive-rate=%.3f latency-p50=%dms latency-p95=%dms%n",
                modality, counts.total, counts.extracted, (double) counts.matches / counts.total,
                counts.benign == 0 ? 0 : (double) counts.falsePositiveBenign / counts.benign,
                percentile(counts.latencies, 0.50), percentile(counts.latencies, 0.95)));
        attackCounts.forEach((type, counts) -> System.out.printf(
                "%s precision=%.3f recall=%.3f (tp=%d fp=%d fn=%d)%n",
                type, ratio(counts.truePositives, counts.truePositives + counts.falsePositives),
                ratio(counts.truePositives, counts.truePositives + counts.falseNegatives),
                counts.truePositives, counts.falsePositives, counts.falseNegatives));

        assertThat(decisionAccuracy).as("multimodal decision accuracy").isGreaterThanOrEqualTo(MINIMUM_DECISION_ACCURACY);
        assertThat(attackPrecision).as("expected attack precision").isGreaterThanOrEqualTo(MINIMUM_ATTACK_RECALL);
        assertThat(attackRecall).as("expected attack recall").isGreaterThanOrEqualTo(MINIMUM_ATTACK_RECALL);
        assertThat(falsePositiveCases).as("benign false-positive cases").isZero();
    }

    private List<EvaluationCase> readCases() throws Exception {
        Path manifest = SAMPLE_DIRECTORY.resolve("evaluation.csv");
        List<String> lines = Files.readAllLines(manifest, StandardCharsets.UTF_8);
        assertThat(lines.getFirst()).isEqualTo("id,modality,file,expected_decision,expected_attack");
        return lines.stream().skip(1).filter(line -> !line.isBlank()).map(line -> {
            String[] fields = line.split(",", 5);
            if (fields.length != 5) {
                throw new IllegalArgumentException("Malformed evaluation row: " + line);
            }
            Set<AttackType> attacks = fields[4].equals("NONE") ? Set.of()
                    : Arrays.stream(fields[4].split("\\|")).map(AttackType::valueOf)
                    .collect(java.util.stream.Collectors.toCollection(() -> EnumSet.noneOf(AttackType.class)));
            return new EvaluationCase(fields[0], fields[1], SAMPLE_DIRECTORY.resolve(fields[2]),
                    Decision.valueOf(fields[3]), attacks);
        }).toList();
    }

    private MockMultipartFile toUpload(EvaluationCase evaluationCase) throws Exception {
        byte[] bytes = Files.readAllBytes(evaluationCase.file());
        return switch (evaluationCase.modality()) {
            case "scanned-pdf" -> upload(evaluationCase, "application/pdf", imageOnlyPdf(bytes));
            case "docx-image" -> upload(evaluationCase,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", imageOnlyDocx(bytes));
            default -> upload(evaluationCase, contentType(evaluationCase.file()), bytes);
        };
    }

    private MockMultipartFile upload(EvaluationCase evaluationCase, String contentType, byte[] content) {
        String fileName = evaluationCase.file().getFileName().toString();
        String uploadName = switch (evaluationCase.modality()) {
            case "scanned-pdf" -> evaluationCase.id() + ".pdf";
            case "docx-image" -> evaluationCase.id() + ".docx";
            default -> fileName;
        };
        return new MockMultipartFile("file", uploadName, contentType, content);
    }

    private byte[] imageOnlyPdf(byte[] imageBytes) throws Exception {
        try (PDDocument document = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            PDPage page = new PDPage(new PDRectangle(900, 400));
            document.addPage(page);
            PDImageXObject image = PDImageXObject.createFromByteArray(document, imageBytes, "ocr-fixture");
            try (PDPageContentStream stream = new PDPageContentStream(document, page)) {
                stream.drawImage(image, 40, 40, 820, 318);
            }
            document.save(output);
            return output.toByteArray();
        }
    }

    private byte[] imageOnlyDocx(byte[] imageBytes) throws Exception {
        try (XWPFDocument document = new XWPFDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            XWPFRun run = document.createParagraph().createRun();
            run.addPicture(new ByteArrayInputStream(imageBytes), XWPFDocument.PICTURE_TYPE_PNG,
                    "evaluation.png", Units.toEMU(6.5), Units.toEMU(2.5));
            document.write(output);
            return output.toByteArray();
        }
    }

    private String contentType(Path file) {
        String name = file.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".png")) return "image/png";
        if (name.endsWith(".pdf")) return "application/pdf";
        if (name.endsWith(".eml")) return "message/rfc822";
        if (name.endsWith(".html")) return "text/html";
        if (name.endsWith(".md")) return "text/markdown";
        return "application/octet-stream";
    }

    private SourceType expectedSourceType(String modality) {
        return switch (modality) {
            case "image" -> SourceType.IMAGE;
            case "scanned-pdf", "native-pdf" -> SourceType.PDF;
            case "docx-image" -> SourceType.WORD_DOCUMENT;
            case "email", "email-image" -> SourceType.EMAIL;
            case "html" -> SourceType.HTML;
            case "markdown" -> SourceType.MARKDOWN;
            case "source-code" -> SourceType.SOURCE_CODE;
            default -> throw new IllegalArgumentException("Unknown modality: " + modality);
        };
    }

    private Decision decide(List<DetectionFinding> findings, double score) {
        if (score >= 0.78) return Decision.BLOCK;
        if (!findings.isEmpty() && score >= 0.48) return Decision.SANITIZE;
        if (!findings.isEmpty()) return Decision.REVIEW;
        return Decision.ALLOW;
    }

    private int percentile(List<Long> values, double percentile) {
        List<Long> sorted = values.stream().sorted().toList();
        int index = (int) Math.ceil(percentile * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(index, sorted.size() - 1))).intValue();
    }

    private double ratio(int numerator, int denominator) {
        return denominator == 0 ? 0.0 : (double) numerator / denominator;
    }

    private void writeReport(List<EvaluationRecord> records, Map<String, ModalityCounts> modalities,
                             Map<AttackType, Counts> attacks,
                             double accuracy, double precision, double recall, double falsePositiveRate,
                             int falsePositives, int extracted, int total) throws Exception {
        Path reportDirectory = Path.of("target", "evaluation");
        Files.createDirectories(reportDirectory);
        List<String> lines = new ArrayList<>();
        lines.add("id,modality,expected_decision,actual_decision,expected_attacks,actual_attacks,extraction_chars,latency_ms");
        for (EvaluationRecord record : records) {
            lines.add(String.join(",", record.evaluationCase().id(), record.evaluationCase().modality(),
                    record.evaluationCase().expectedDecision().name(), record.actualDecision().name(),
                    joinAttacks(record.evaluationCase().expectedAttacks()), joinAttacks(record.actualAttacks()),
                    Integer.toString(record.extractedCharacters()), Long.toString(record.elapsedMillis())));
        }
        lines.add("");
        lines.add("summary,total_cases,extraction_successes,decision_accuracy,expected_attack_precision,"
                + "expected_attack_recall,benign_false_positive_rate,benign_false_positive_cases");
        lines.add(String.join(",", "overall", Integer.toString(total), Integer.toString(extracted),
                Double.toString(accuracy), Double.toString(precision), Double.toString(recall),
                Double.toString(falsePositiveRate), Integer.toString(falsePositives)));
        lines.add("");
        lines.add("modality,cases,extraction_successes,decision_matches,benign_cases,benign_false_positives,"
                + "latency_p50_ms,latency_p95_ms");
        modalities.forEach((modality, counts) -> lines.add(String.join(",", modality, Integer.toString(counts.total),
                Integer.toString(counts.extracted), Integer.toString(counts.matches), Integer.toString(counts.benign),
                Integer.toString(counts.falsePositiveBenign), Integer.toString(percentile(counts.latencies, 0.50)),
                Integer.toString(percentile(counts.latencies, 0.95)))));
        lines.add("");
        lines.add("attack_type,true_positives,false_positives,false_negatives,precision,recall");
        attacks.forEach((type, counts) -> lines.add(String.join(",", type.name(),
                Integer.toString(counts.truePositives), Integer.toString(counts.falsePositives),
                Integer.toString(counts.falseNegatives),
                Double.toString(ratio(counts.truePositives, counts.truePositives + counts.falsePositives)),
                Double.toString(ratio(counts.truePositives, counts.truePositives + counts.falseNegatives)))));
        Files.write(reportDirectory.resolve("multimodal-reliability.csv"), lines, StandardCharsets.UTF_8);
    }

    private String joinAttacks(Set<AttackType> attacks) {
        return attacks.stream().sorted().map(Enum::name).collect(java.util.stream.Collectors.joining("|"));
    }

    private record EvaluationCase(String id, String modality, Path file, Decision expectedDecision,
                                  Set<AttackType> expectedAttacks) {}

    private record EvaluationRecord(EvaluationCase evaluationCase, Decision actualDecision,
                                   Set<AttackType> actualAttacks, int extractedCharacters, long elapsedMillis) {}

    private static final class ModalityCounts {
        private int total;
        private int extracted;
        private int matches;
        private int benign;
        private int falsePositiveBenign;
        private final List<Long> latencies = new ArrayList<>();

        private void record(boolean matches, boolean benign, Set<AttackType> attacks, long latency) {
            total++;
            extracted++;
            if (matches) this.matches++;
            if (benign) {
                this.benign++;
                if (!attacks.isEmpty()) falsePositiveBenign++;
            }
            latencies.add(latency);
        }
    }

    private static final class Counts {
        private int truePositives;
        private int falsePositives;
        private int falseNegatives;
    }
}
