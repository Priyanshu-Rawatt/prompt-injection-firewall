package com.et.hackathon.firewall.service.parser;

import com.et.hackathon.firewall.config.FirewallProperties;
import com.et.hackathon.firewall.dto.SourceType;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayOutputStream;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContentParserServiceTest {
    private final ContentParserService parser = new ContentParserService(
            new FirewallProperties("test", 120_000, 0.78, 0.48, null, new FirewallProperties.Ocr(
                    false, "tesseract", 20, 30, 150, 40_000_000)));

    @Test
    void extractsPdfTextAndMarksPageProvenance() throws Exception {
        byte[] pdf;
        try (PDDocument document = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            document.addPage(new PDPage());
            try (PDPageContentStream stream = new PDPageContentStream(document, document.getPage(0))) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("A harmless test document");
                stream.endText();
            }
            document.save(output);
            pdf = output.toByteArray();
        }

        var parsed = parser.parse(new MockMultipartFile("file", "sample.pdf", "application/pdf", pdf));

        assertThat(parsed.getSourceType()).isEqualTo(SourceType.PDF);
        assertThat(parsed.getText()).contains("[PDF page 1]", "A harmless test document");
        assertThat(parsed.getExtractionDetails()).containsExactly("PDF page 1: native text extracted");
    }

    @Test
    void rejectsScannedPdfWhenOcrIsDisabledInsteadOfTreatingItAsSafe() throws Exception {
        byte[] pdf;
        try (PDDocument document = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            document.addPage(new PDPage());
            document.save(output);
            pdf = output.toByteArray();
        }

        assertThatThrownBy(() -> parser.parse(new MockMultipartFile("file", "scan.pdf", "application/pdf", pdf)))
                .isInstanceOf(ContentExtractionException.class)
                .hasMessageContaining("OCR is disabled");
    }

    @Test
    void rejectsPdfWithNativeTextAndEmbeddedImageWhenOcrIsDisabled() throws Exception {
        byte[] pdf;
        try (PDDocument document = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream();
             ByteArrayOutputStream png = new ByteArrayOutputStream()) {
            BufferedImage image = new BufferedImage(10, 10, BufferedImage.TYPE_INT_RGB);
            ImageIO.write(image, "png", png);
            image.flush();
            PDPage page = new PDPage();
            document.addPage(page);
            try (PDPageContentStream stream = new PDPageContentStream(document, page)) {
                stream.beginText();
                stream.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                stream.newLineAtOffset(50, 700);
                stream.showText("Native page text");
                stream.endText();
                stream.drawImage(PDImageXObject.createFromByteArray(document, png.toByteArray(), "embedded"), 50, 600);
            }
            document.save(output);
            pdf = output.toByteArray();
        }

        assertThatThrownBy(() -> parser.parse(new MockMultipartFile("file", "mixed.pdf", "application/pdf", pdf)))
                .isInstanceOf(ContentExtractionException.class)
                .hasMessageContaining("image content that OCR must inspect");
    }

    @Test
    void extractsDocxText() throws Exception {
        byte[] docx;
        try (XWPFDocument document = new XWPFDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            document.createParagraph().createRun().setText("A harmless Word document");
            document.write(output);
            docx = output.toByteArray();
        }

        var parsed = parser.parse(new MockMultipartFile("file", "sample.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document", docx));

        assertThat(parsed.getSourceType()).isEqualTo(SourceType.WORD_DOCUMENT);
        assertThat(parsed.getText()).contains("A harmless Word document");
    }

    @Test
    void rejectsUnknownFileTypesRatherThanInspectingBinaryAsText() {
        assertThatThrownBy(() -> parser.parse(new MockMultipartFile("file", "payload.bin",
                "application/octet-stream", new byte[]{0, 1, 2})))
                .isInstanceOf(ContentExtractionException.class)
                .hasMessageContaining("Unsupported file type");
    }

    @Test
    void extractsTransferEncodedEmailText() {
        byte[] email = ("Content-Type: text/plain; charset=UTF-8\n"
                + "Content-Transfer-Encoding: base64\n\nYW55IGJvZHk=").getBytes(java.nio.charset.StandardCharsets.UTF_8);

        var parsed = parser.parse(new MockMultipartFile("file", "message.eml", "message/rfc822", email));

        assertThat(parsed.getSourceType()).isEqualTo(SourceType.EMAIL);
        assertThat(parsed.getText()).contains("any body");
    }

    @Test
    void rejectsUnsupportedEmailAttachmentInsteadOfSkippingIt() {
        byte[] email = ("MIME-Version: 1.0\r\n"
                + "Content-Type: multipart/mixed; boundary=\"inspection-boundary\"\r\n\r\n"
                + "--inspection-boundary\r\n"
                + "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
                + "Please review the attached report.\r\n"
                + "--inspection-boundary\r\n"
                + "Content-Type: application/octet-stream\r\n"
                + "Content-Disposition: attachment; filename=\"payload.bin\"\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\n"
                + "AQID\r\n"
                + "--inspection-boundary--\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertThatThrownBy(() -> parser.parse(new MockMultipartFile("file", "message.eml",
                "message/rfc822", email)))
                .isInstanceOf(ContentExtractionException.class)
                .hasMessageContaining("Unsupported email MIME part");
    }

    @Test
    void rejectsImageWhenConfiguredOcrCommandCannotRun() throws Exception {
        BufferedImage image = new BufferedImage(10, 10, BufferedImage.TYPE_INT_RGB);
        byte[] png;
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            ImageIO.write(image, "png", output);
            png = output.toByteArray();
        } finally {
            image.flush();
        }
        var ocrParser = new ContentParserService(new FirewallProperties("test", 120_000, 0.78, 0.48, null,
                new FirewallProperties.Ocr(true, "missing-tesseract-command-for-test", 1, 30, 150, 40_000_000)));

        assertThatThrownBy(() -> ocrParser.parse(new MockMultipartFile("file", "sample.png", "image/png", png)))
                .isInstanceOf(ContentExtractionException.class)
                .hasMessageContaining("File inspection incomplete");
    }
}
