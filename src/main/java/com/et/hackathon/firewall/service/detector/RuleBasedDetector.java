package com.et.hackathon.firewall.service.detector;

import com.et.hackathon.firewall.dto.AttackType;
import com.et.hackathon.firewall.dto.DetectionFinding;
import com.et.hackathon.firewall.dto.SourceType;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class RuleBasedDetector {
    private record Rule(AttackType type, String source, String explanation, Pattern pattern) {}
    private record Signal(AttackType type, double weight, String evidence, String source, String explanation) {}

    private static final double MINIMUM_SIGNAL_WEIGHT = 0.35;
    private static final Pattern EDUCATIONAL_CONTEXT = Pattern.compile(
            "(?i)\\b(what (?:does|is)|how do attackers|how to defend|explain\\w*|example|training|educational|research|"
                    + "discuss\\w*|how to defend|security article|phrase|term|definition|documentation)\\b");
    private static final Pattern OBJECT_MENTION = Pattern.compile(
            "(?i)\\b(phrase|term|string|wording|example|attack like|instruction like)\\b[^.!?\\n]{0,80}$");
    private static final Pattern IMPERATIVE = Pattern.compile(
            "(?i)^(?:please\\s+)?(?:ignore|disregard|forget|override|reveal|show|print|leak|dump|decode|unpack|"
                    + "disclose|expose|send|give|provide|paste|extract|call|invoke|execute|run|use|"
                    + "assume|act as|pretend|switch to)\\b");
    private static final Pattern ASSISTANT_DIRECTIVE = Pattern.compile(
            "(?i)\\b(?:you must|you are now|from now on|your new role|assume the role|act as|"
                    + "pretend to be|assistant\\s*[:,]|system\\s*[:,]|developer\\s*[:,])");
    private static final Pattern PROTECTED_ASSET = Pattern.compile(
            "(?i)\\b(?:system prompt|developer message|hidden prompt|private context|api key|"
                    + "access token|bearer token|password|credential|customer records|database|"
                    + "shell|browser|filesystem|safety policy|security policy)\\b");
    private static final Pattern EXTERNAL_INSTRUCTION_MARKER = Pattern.compile(
            "(?i)(assistant\\s*:|system\\s*:|developer\\s*:|do not tell the user|"
                    + "when the agent|follow these instructions)");

    private final List<Rule> rules = List.of(
            new Rule(AttackType.INSTRUCTION_OVERRIDE, "RULE_OVERRIDE",
                    "Attempts to supersede previously trusted instructions.",
                    Pattern.compile("(?i)(ignore|disregard|forget|override)\\s+(?:(?:all|any|the|previous|prior|above|system|developer|safety)\\s+){0,3}(instructions|rules|policies|messages)")),
            new Rule(AttackType.ROLE_CHANGE, "RULE_ROLE",
                    "Attempts to reassign the model or agent a privileged role.",
                    Pattern.compile("(?i)(you are now|act as|pretend to be|switch to|assume the role of)\\s+[^.\\n]{0,100}")),
            new Rule(AttackType.SECRET_EXTRACTION, "RULE_SECRET",
                    "Requests hidden prompts, private context, secrets, or protected data.",
                    Pattern.compile("(?i)(reveal|show|print|leak|dump|disclose|expose)\\s+(the|your|all)?\\s*(system prompt|developer message|hidden prompt|private context|secret|confidential|internal instructions)")),
            new Rule(AttackType.TOOL_ABUSE, "RULE_TOOL",
                    "Attempts to invoke tools or actions outside the intended task or policy.",
                    Pattern.compile("(?i)(call|invoke|execute|run|use)\\s+(the\\s+)?(browser|shell|terminal|database|admin|filesystem|email|payment|http)\\s*(tool|function|command|api)?")),
            new Rule(AttackType.CREDENTIAL_THEFT, "RULE_CRED",
                    "Attempts to solicit credentials, tokens, API keys, or passwords.",
                    Pattern.compile("(?i)(send|give|provide|paste|reveal|extract|show)\\s+(me|us|to me)?\\s*(your|the)?\\s*(password|passcode|otp|one[- ]time code|api key|access token|bearer token|secret key|credential)")),
            new Rule(AttackType.CONTEXT_POISONING, "RULE_CONTEXT",
                    "Introduces fake authority or attempts to alter trusted context/memory.",
                    Pattern.compile("(?i)(system message|developer message|trusted source|security policy|memory update|authoritative instruction|highest priority)\\s*[:=-]")),
            new Rule(AttackType.MULTI_STEP_JAILBREAK, "RULE_MULTI_STEP",
                    "Uses staged instructions to progressively bypass a safety or policy boundary.",
                    Pattern.compile("(?is)(step\\s*1.{0,400}step\\s*2|first.{0,250}then.{0,250}(ignore|bypass|reveal|execute)|phase\\s*1.{0,400}phase\\s*2)")),
            new Rule(AttackType.ENCODED_INSTRUCTIONS, "RULE_ENCODED",
                    "Contains a decodable payload that resembles an instruction override or data-exfiltration request.",
                    Pattern.compile("(?i)(base64|b64|url[- ]encoded|hex encoded|decode this|percent[- ]encoded)"))
    );

    public DetectionResult analyze(String raw, String decoded, SourceType sourceType) {
        String normalized = Objects.toString(raw, "");
        String searchable = decoded == null || decoded.isBlank() ? normalized : decoded;
        SourceType actualSource = sourceType == null ? SourceType.UNKNOWN : sourceType;
        List<Signal> signals = new ArrayList<>();

        for (Rule rule : rules) {
            var matcher = rule.pattern().matcher(searchable);
            Signal best = null;
            while (matcher.find()) {
                double weight = contextAdjustedWeight(searchable, matcher.start(), matcher.end(), rule.type(), actualSource);
                if (weight < MINIMUM_SIGNAL_WEIGHT) continue;
                String evidence = matcher.group().replaceAll("\\s+", " ").trim();
                Signal candidate = new Signal(rule.type(), weight, evidence, rule.source(), rule.explanation());
                if (best == null || candidate.weight() > best.weight()) best = candidate;
            }
            if (best != null) signals.add(best);
        }

        if (isUntrustedSource(actualSource)) {
            boolean hasDirectFinding = signals.stream().anyMatch(signal -> signal.type() == AttackType.INSTRUCTION_OVERRIDE
                    || signal.type() == AttackType.SECRET_EXTRACTION
                    || signal.type() == AttackType.TOOL_ABUSE
                    || signal.type() == AttackType.CREDENTIAL_THEFT
                    || signal.type() == AttackType.CONTEXT_POISONING);
            if (hasDirectFinding) {
                signals.add(new Signal(AttackType.INDIRECT_PROMPT_INJECTION, 0.20,
                        "Instruction-like text embedded in untrusted external content", "RULE_INDIRECT",
                        "External content is treated as data; instruction-like text must not control the agent."));
            } else {
                var marker = EXTERNAL_INSTRUCTION_MARKER.matcher(searchable);
                if (marker.find()) {
                    double weight = contextAdjustedWeight(searchable, marker.start(), marker.end(),
                            AttackType.INDIRECT_PROMPT_INJECTION, actualSource);
                    if (weight >= MINIMUM_SIGNAL_WEIGHT) {
                        signals.add(new Signal(AttackType.INDIRECT_PROMPT_INJECTION, weight,
                                marker.group(), "RULE_INDIRECT",
                                "Instruction-like text embedded in untrusted external content must be treated as data."));
                    }
                }
            }
        }

        addEncodedPayloadSignals(normalized, signals);
        String urlDecoded = safeUrlDecode(normalized);
        if (!urlDecoded.equals(normalized) && containsInstructionSignals(urlDecoded.toLowerCase(Locale.ROOT))
                && signals.stream().noneMatch(signal -> signal.type() == AttackType.ENCODED_INSTRUCTIONS)) {
            signals.add(new Signal(AttackType.ENCODED_INSTRUCTIONS, 0.82,
                    "URL-decoded content contains instruction signals", "RULE_URL_DECODE",
                    "URL-encoded content is normalized before model access."));
        }

        Set<AttackType> uniqueTypes = EnumSet.noneOf(AttackType.class);
        signals.forEach(signal -> uniqueTypes.add(signal.type()));
        double score = signals.stream().mapToDouble(Signal::weight).sum();
        if (uniqueTypes.size() > 1) score += 0.10 * (uniqueTypes.size() - 1);
        score = Math.min(1.0, score);

        List<DetectionFinding> findings = signals.stream()
                .collect(java.util.stream.Collectors.toMap(Signal::type, signal -> signal,
                        (left, right) -> left.weight() >= right.weight() ? left : right,
                        () -> new EnumMap<>(AttackType.class)))
                .values().stream()
                .map(signal -> new DetectionFinding(signal.type(), Math.min(1.0, signal.weight()
                                + (uniqueTypes.size() > 1 ? 0.10 : 0.0)),
                        signal.evidence(), signal.source(), signal.explanation()))
                .sorted(Comparator.comparing(DetectionFinding::getConfidence).reversed())
                .toList();
        return new DetectionResult(findings, score);
    }

    private double contextAdjustedWeight(String text, int start, int end, AttackType type, SourceType source) {
        String sentence = sentenceAt(text, start, end);
        int sentenceStart = sentenceStart(text, start);
        double weight = 0.50;
        boolean mentionContext = insideQuoteOrCode(text, start) || insideMarkdownQuote(text, start)
                || hasEducationalFraming(sentence)
                || sentence.stripTrailing().endsWith("?");

        if (insideQuoteOrCode(text, start) || insideMarkdownQuote(text, start)) weight -= 0.38;
        if (hasEducationalFraming(sentence)) weight -= 0.35;
        if (isObjectMention(text, start)) weight -= 0.18;
        if (sentence.stripTrailing().endsWith("?")) weight -= 0.20;

        int relativeStart = Math.max(0, start - sentenceStart);
        String matchedSentence = sentence.substring(Math.min(relativeStart, sentence.length()));
        if (IMPERATIVE.matcher(sentence.stripLeading()).find()
                || IMPERATIVE.matcher(matchedSentence.stripLeading()).find()
                || ASSISTANT_DIRECTIVE.matcher(sentence).find()) {
            weight += 0.30;
        }
        if (PROTECTED_ASSET.matcher(sentence).find()
                && type != AttackType.MULTI_STEP_JAILBREAK
                && type != AttackType.ENCODED_INSTRUCTIONS) {
            weight += 0.12;
        }
        if (type == AttackType.CONTEXT_POISONING) weight += 0.30;
        if (type == AttackType.MULTI_STEP_JAILBREAK && !mentionContext) weight += 0.30;
        if (isUntrustedSource(source) && (IMPERATIVE.matcher(sentence.stripLeading()).find()
                || ASSISTANT_DIRECTIVE.matcher(sentence).find())) {
            weight += 0.12;
        }
        return Math.max(0.0, Math.min(1.0, weight));
    }

    private boolean hasEducationalFraming(String sentence) {
        return EDUCATIONAL_CONTEXT.matcher(sentence).find();
    }

    private boolean isObjectMention(String text, int start) {
        int from = Math.max(0, start - 85);
        return OBJECT_MENTION.matcher(text.substring(from, start)).find();
    }

    private String sentenceAt(String text, int start, int end) {
        int from = sentenceStart(text, start);
        int to = text.length();
        for (char boundary : new char[]{'.', '!', '?', '\n'}) {
            int index = text.indexOf(boundary, end);
            if (index >= 0) to = Math.min(to, index + (boundary == '\n' ? 0 : 1));
        }
        return text.substring(from, Math.max(from, to)).trim();
    }

    private int sentenceStart(String text, int position) {
        int from = 0;
        for (char boundary : new char[]{'.', '!', '?', '\n'}) {
            from = Math.max(from, text.lastIndexOf(boundary, Math.max(0, position - 1)) + 1);
        }
        while (from < position && Character.isWhitespace(text.charAt(from))) from++;
        return from;
    }

    private boolean insideQuoteOrCode(String text, int position) {
        if (countBefore(text, "\"", position) % 2 != 0
                || countBefore(text, "'", position) % 2 != 0
                || countBefore(text, "`", position) % 2 != 0
                || countBefore(text, "“", position) > countBefore(text, "”", position)
                || countBefore(text, "‘", position) > countBefore(text, "’", position)) {
            return true;
        }
        return countBefore(text, "```", position) % 2 != 0;
    }

    private int countBefore(String text, String token, int position) {
        int count = 0;
        int next = 0;
        while ((next = text.indexOf(token, next)) >= 0 && next < position) {
            count++;
            next += token.length();
        }
        return count;
    }

    private boolean insideMarkdownQuote(String text, int position) {
        int lineStart = text.lastIndexOf('\n', Math.max(0, position - 1)) + 1;
        int first = lineStart;
        while (first < text.length() && Character.isWhitespace(text.charAt(first)) && text.charAt(first) != '\n') first++;
        return first < text.length() && text.charAt(first) == '>';
    }

    private void addEncodedPayloadSignals(String normalized, List<Signal> signals) {
        for (String token : normalized.split("\\s+")) {
            String candidate = token.replaceAll("[^A-Za-z0-9+/=_-]", "");
            if (candidate.length() < 24 || candidate.length() % 4 != 0
                    || !candidate.matches("[A-Za-z0-9+/=_-]+")) continue;
            try {
                String decoded = new String(Base64.getDecoder().decode(candidate), StandardCharsets.UTF_8);
                if (containsInstructionSignals(decoded.toLowerCase(Locale.ROOT))) {
                    signals.add(new Signal(AttackType.ENCODED_INSTRUCTIONS, 0.82,
                            "Decodable Base64-like token contains instruction signals",
                            "RULE_B64_DECODE", "Encoded content is decoded for inspection but never executed."));
                    return;
                }
            } catch (IllegalArgumentException ignored) {
                // Not valid Base64; continue.
            }
        }
    }

    private boolean isUntrustedSource(SourceType source) {
        return switch (source) {
            case WEB_PAGE, PDF, EMAIL, MARKDOWN, HTML, WORD_DOCUMENT, OCR_TEXT, SOURCE_CODE, IMAGE,
                    API_RESPONSE -> true;
            default -> false;
        };
    }

    private boolean containsInstructionSignals(String low) {
        return low.contains("ignore previous") || low.contains("ignore all previous") || low.contains("ignore all prior")
                || low.contains("reveal the system prompt") || low.contains("reveal hidden instructions")
                || low.contains("provide the api key") || low.contains("send the password")
                || low.contains("execute this command") || low.contains("act as the system")
                || low.contains("developer message");
    }

    private String safeUrlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return value;
        }
    }

    public record DetectionResult(List<DetectionFinding> findings, double score) {}
}
