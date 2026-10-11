package com.et.hackathon.firewall.service.parser;

import com.et.hackathon.firewall.config.FirewallProperties;
import com.et.hackathon.firewall.dto.ParsedContent;
import com.et.hackathon.firewall.dto.SourceType;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.poi.xwpf.extractor.XWPFWordExtractor;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFPictureData;
import org.jsoup.Jsoup;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

@Service
public class ContentParserService {
    private static final int MAX_IMAGE_BYTES = 10_000_000;
    private static final int MAX_EMAIL_PARTS = 100;
    private final FirewallProperties properties;

    public ContentParserService(FirewallProperties properties) {
        this.properties = properties;
    }

    public ParsedContent parse(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new ContentExtractionException("Uploaded file is empty");
        }
        String name = file.getOriginalFilename() == null ? "upload" : file.getOriginalFilename();
        String mime = file.getContentType() == null ? "application/octet-stream" : file.getContentType();
        String lower = name.toLowerCase(Locale.ROOT);

        try {
            byte[] bytes = file.getBytes();
            if (lower.endsWith(".pdf") || mime.equalsIgnoreCase("application/pdf")) {
                return parsePdf(bytes, name, mime);
            }
            if (lower.endsWith(".docx") || mime.equalsIgnoreCase("application/vnd.openxmlformats-officedocument.wordprocessingml.document")) {
                return parseDocx(bytes, name, mime);
            }
            if (lower.endsWith(".html") || lower.endsWith(".htm") || mime.equalsIgnoreCase("text/html")) {
                return parsed(Jsoup.parse(new ByteArrayInputStream(bytes), null, "").text(), SourceType.HTML,
                        name, mime, List.of("HTML visible text extracted"));
            }
            if (lower.endsWith(".eml") || mime.equalsIgnoreCase("message/rfc822")) {
                return parseEmail(bytes, name, mime);
            }
            if (isImage(lower, mime)) {
                return parsed(runTesseract(bytes, name), SourceType.IMAGE, name, mime,
                        List.of("Image OCR (English, Tesseract)"));
            }
            if (lower.endsWith(".md")) {
                return parsed(new String(bytes, StandardCharsets.UTF_8), SourceType.MARKDOWN,
                        name, mime, List.of("Markdown text decoded as UTF-8"));
            }
            if (looksLikeSourceCode(lower)) {
                return parsed(new String(bytes, StandardCharsets.UTF_8), SourceType.SOURCE_CODE,
                        name, mime, List.of("Source text decoded as UTF-8"));
            }
            throw new IOException("Unsupported file type; refusing to inspect an unparsed upload");
        } catch (ContentExtractionException ex) {
            throw ex;
        } catch (IOException ex) {
            throw new ContentExtractionException("File inspection incomplete: " + ex.getMessage(), ex);
        } catch (MessagingException ex) {
            throw new ContentExtractionException("File inspection incomplete: invalid email MIME structure", ex);
        }
    }

    private ParsedContent parseEmail(byte[] bytes, String name, String mime)
            throws IOException, MessagingException {
        MimeMessage message = new MimeMessage(Session.getInstance(new Properties()), new ByteArrayInputStream(bytes));
        StringBuilder text = new StringBuilder("[Email headers]\n");
        var headers = message.getAllHeaderLines();
        while (headers.hasMoreElements()) {
            text.append(headers.nextElement()).append('\n');
        }
        List<String> details = new ArrayList<>();
        int[] partCount = {0};
        int[] imageCount = {0};
        extractEmailPart(message, text, details, partCount, imageCount, name);
        if (imageCount[0] == 0) {
            details.add("Email headers and MIME text parts extracted");
        }
        return parsed(text.toString(), SourceType.EMAIL, name, mime, details);
    }

    private void extractEmailPart(Part part, StringBuilder text, List<String> details, int[] partCount,
                                  int[] imageCount, String source) throws IOException, MessagingException {
        Object content = part.getContent();
        if (content instanceof Multipart multipart) {
            for (int index = 0; index < multipart.getCount(); index++) {
                extractEmailPart(multipart.getBodyPart(index), text, details, partCount, imageCount, source);
            }
            return;
        }
        if (content instanceof Message nestedMessage) {
            extractEmailPart(nestedMessage, text, details, partCount, imageCount, source);
            return;
        }
        if (++partCount[0] > MAX_EMAIL_PARTS) {
            throw new IOException("Email contains more MIME parts than the configured limit");
        }

        String contentType = part.getContentType().toLowerCase(Locale.ROOT);
        if (contentType.startsWith("text/plain")) {
            if (content instanceof String body && !body.isBlank()) {
                text.append("\n[Email text]\n").append(body).append('\n');
                details.add("Email plain-text part extracted");
            }
            return;
        }
        if (contentType.startsWith("text/html")) {
            if (content instanceof String body) {
                String visibleText = Jsoup.parse(body).text();
                if (!visibleText.isBlank()) {
                    text.append("\n[Email HTML text]\n").append(visibleText).append('\n');
                    details.add("Email HTML text extracted");
                }
            }
            return;
        }
        if (contentType.startsWith("image/")) {
            byte[] imageBytes;
            try (var input = part.getInputStream()) {
                imageBytes = input.readNBytes(MAX_IMAGE_BYTES + 1);
            }
            if (imageBytes.length > MAX_IMAGE_BYTES) {
                throw new IOException("Email image part exceeds the 10 MB OCR input limit");
            }
            int imageNumber = ++imageCount[0];
            String imageText = runTesseract(imageBytes, source + " image part " + imageNumber).trim();
            if (imageText.isBlank()) {
                throw new IOException("Email image part " + imageNumber
                        + " produced no readable text; inspection is incomplete");
            }
            text.append("\n[Email image ").append(imageNumber).append(" OCR]\n").append(imageText).append('\n');
            details.add("Email image part " + imageNumber + ": OCR-scanned");
            return;
        }
        throw new IOException("Unsupported email MIME part " + contentType
                + "; refusing to skip uninspected attachment content");
    }

    private ParsedContent parsePdf(byte[] bytes, String name, String mime) throws IOException {
        try (PDDocument document = Loader.loadPDF(bytes)) {
            int pageCount = document.getNumberOfPages();
            if (pageCount == 0 || pageCount > properties.ocr().maxPages()) {
                throw new IOException("PDF page count is outside the configured supported range");
            }
            PDFRenderer renderer = new PDFRenderer(document);
            PDFTextStripper stripper = new PDFTextStripper();
            StringBuilder text = new StringBuilder();
            List<String> details = new ArrayList<>();
            for (int page = 1; page <= pageCount; page++) {
                stripper.setStartPage(page);
                stripper.setEndPage(page);
                String pageText = stripper.getText(document).trim();
                boolean pageContainsImage = containsImageXObject(document.getPage(page - 1));
                if (pageText.isBlank() || pageContainsImage) {
                    if (!properties.ocr().enabled()) {
                        throw new IOException("PDF page " + page
                                + " contains scanned or image content that OCR must inspect, but OCR is disabled");
                    }
                    verifyPagePixelLimit(document, page - 1);
                    BufferedImage rendered = renderer.renderImageWithDPI(page - 1, properties.ocr().dpi());
                    byte[] imageBytes;
                    try (ByteArrayOutputStream imageOutput = new ByteArrayOutputStream()) {
                        if (!ImageIO.write(rendered, "png", imageOutput)) {
                            throw new IOException("Could not encode PDF page " + page + " for OCR");
                        }
                        imageBytes = imageOutput.toByteArray();
                    } finally {
                        rendered.flush();
                    }
                    String ocrText = runTesseract(imageBytes, name + " page " + page).trim();
                    if (ocrText.isBlank()) {
                        throw new IOException("PDF page " + page + " produced no readable OCR text; inspection is incomplete");
                    }
                    if (pageText.isBlank()) {
                        pageText = ocrText;
                        details.add("PDF page " + page + ": rendered and OCR-scanned");
                    } else {
                        pageText += "\n[OCR text]\n" + ocrText;
                        details.add("PDF page " + page + ": native text and embedded images OCR-scanned");
                    }
                } else {
                    details.add("PDF page " + page + ": native text extracted");
                }
                if (pageText.isBlank()) {
                    throw new IOException("PDF page " + page + " produced no readable text; inspection is incomplete");
                }
                text.append("[PDF page ").append(page).append("]\n").append(pageText).append('\n');
            }
            return parsed(text.toString(), SourceType.PDF, name, mime, details);
        }
    }

    private ParsedContent parseDocx(byte[] bytes, String name, String mime) throws IOException {
        try (XWPFDocument document = new XWPFDocument(new ByteArrayInputStream(bytes));
             XWPFWordExtractor extractor = new XWPFWordExtractor(document)) {
            StringBuilder text = new StringBuilder(extractor.getText());
            List<String> details = new ArrayList<>();
            details.add("DOCX text extracted");
            int imageNumber = 0;
            for (XWPFPictureData picture : document.getAllPictures()) {
                imageNumber++;
                if (!properties.ocr().enabled()) {
                    throw new IOException("DOCX contains embedded images and OCR is disabled");
                }
                String imageText = runTesseract(picture.getData(), name + " image " + imageNumber).trim();
                if (imageText.isBlank()) {
                    throw new IOException("DOCX embedded image " + imageNumber
                            + " produced no readable text; inspection is incomplete");
                }
                text.append("\n[DOCX embedded image ").append(imageNumber).append("]\n").append(imageText);
                details.add("DOCX embedded image " + imageNumber + ": OCR-scanned");
            }
            return parsed(text.toString(), SourceType.WORD_DOCUMENT, name, mime, details);
        }
    }

    private ParsedContent parsed(String text, SourceType type, String name, String mime, List<String> details) {
        if (text == null || text.isBlank()) {
            throw new ContentExtractionException("No readable content was extracted; refusing to treat the upload as safe");
        }
        return new ParsedContent(text, type, name, mime, details);
    }

    private void verifyPagePixelLimit(PDDocument document, int pageIndex) throws IOException {
        var box = document.getPage(pageIndex).getCropBox();
        double width = box.getWidth() / 72.0 * properties.ocr().dpi();
        double height = box.getHeight() / 72.0 * properties.ocr().dpi();
        if (width * height > properties.ocr().maxPixels()) {
            throw new IOException("PDF page exceeds the configured OCR pixel limit");
        }
    }

    private boolean containsImageXObject(PDPage page) throws IOException {
        var resources = page.getResources();
        if (resources == null) return false;
        for (COSName name : resources.getXObjectNames()) {
            if (resources.getXObject(name) instanceof PDImageXObject) return true;
        }
        return false;
    }

    private boolean isImage(String name, String mime) {
        return mime.startsWith("image/") || name.endsWith(".png") || name.endsWith(".jpg")
                || name.endsWith(".jpeg") || name.endsWith(".webp") || name.endsWith(".bmp");
    }

    private boolean looksLikeSourceCode(String name) {
        return name.endsWith(".java") || name.endsWith(".js") || name.endsWith(".ts")
                || name.endsWith(".py") || name.endsWith(".go") || name.endsWith(".kt")
                || name.endsWith(".sql") || name.endsWith(".sh") || name.endsWith(".xml")
                || name.endsWith(".yaml") || name.endsWith(".yml") || name.endsWith(".json");
    }

    private String runTesseract(byte[] bytes, String source) throws IOException {
        if (!properties.ocr().enabled()) {
            throw new IOException("OCR is disabled; refusing to pass image content without inspection");
        }
        if (bytes.length > MAX_IMAGE_BYTES) {
            throw new IOException("Image exceeds the 10 MB OCR input limit: " + source);
        }
        try (ImageInputStream imageInput = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
            if (imageInput == null) throw new IOException("Unsupported or invalid image content in " + source);
            Iterator<ImageReader> readers = ImageIO.getImageReaders(imageInput);
            if (!readers.hasNext()) throw new IOException("Unsupported or invalid image content in " + source);
            ImageReader reader = readers.next();
            try {
                reader.setInput(imageInput, true, true);
                long pixels = (long) reader.getWidth(0) * reader.getHeight(0);
                if (pixels > properties.ocr().maxPixels()) {
                    throw new IOException("Image exceeds the configured OCR pixel limit: " + source);
                }
            } finally {
                reader.dispose();
            }
        }

        Path input = Files.createTempFile("firewall-ocr-", ".img");
        Path outputBase = Files.createTempFile("firewall-ocr-out-", "");
        Files.deleteIfExists(outputBase);
        try {
            Files.write(input, bytes);
            Process process = new ProcessBuilder(properties.ocr().command(), input.toString(), outputBase.toString(), "-l", "eng")
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            boolean finished;
            try {
                finished = process.waitFor(properties.ocr().timeoutSeconds(), TimeUnit.SECONDS);
            } catch (InterruptedException ex) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new IOException("OCR interrupted for " + source, ex);
            }
            if (!finished) {
                process.destroyForcibly();
                throw new IOException("OCR timed out for " + source);
            }
            if (process.exitValue() != 0) {
                throw new IOException("OCR failed for " + source + " (Tesseract exit code " + process.exitValue() + ")");
            }
            Path txt = Path.of(outputBase + ".txt");
            if (!Files.exists(txt)) throw new IOException("OCR produced no output for " + source);
            return Files.readString(txt);
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(Path.of(outputBase + ".txt"));
        }
    }
}
