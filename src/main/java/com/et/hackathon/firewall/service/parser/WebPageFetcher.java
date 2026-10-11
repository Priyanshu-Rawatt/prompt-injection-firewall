package com.et.hackathon.firewall.service.parser;

import com.et.hackathon.firewall.dto.ParsedContent;
import com.et.hackathon.firewall.dto.SourceType;
import org.jsoup.Jsoup;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;

@Service
public class WebPageFetcher {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public ParsedContent fetch(String url) throws Exception {
        URI uri = URI.create(url);
        validate(uri);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("User-Agent", "ET-Prompt-Firewall/1.0")
                .GET()
                .build();
        HttpResponse<java.io.InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() >= 300) {
            response.body().close();
            throw new IllegalStateException("Web fetch failed: HTTP " + response.statusCode()
                    + "; redirects are not followed");
        }
        byte[] body;
        try (var input = response.body()) {
            body = input.readNBytes(2_000_001);
        }
        if (body.length > 2_000_000) throw new IllegalArgumentException("Web page exceeds 2 MB inspection limit");
        String text = Jsoup.parse(new java.io.ByteArrayInputStream(body), null, uri.toString()).text();
        if (text.isBlank()) throw new IOException("Web page contains no extractable text");
        return new ParsedContent(text, SourceType.WEB_PAGE, uri.getHost(),
                response.headers().firstValue("content-type").orElse("text/html"),
                java.util.List.of("Web page visible text extracted"));
    }

    private void validate(URI uri) {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("Only http/https URLs are accepted");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) throw new IllegalArgumentException("URL host is required");
        if (uri.getUserInfo() != null) throw new IllegalArgumentException("URL user-info is not allowed");
        try {
            if (Arrays.stream(InetAddress.getAllByName(host)).anyMatch(this::isNonPublicAddress)) {
                throw new IllegalArgumentException("Private/local network hosts are not allowed");
            }
        } catch (java.net.UnknownHostException ex) {
            throw new IllegalArgumentException("URL host could not be resolved", ex);
        }
    }

    private boolean isNonPublicAddress(InetAddress address) {
        byte[] bytes = address.getAddress();
        boolean uniqueLocalIpv6 = bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
        boolean sharedIpv4 = bytes.length == 4 && (bytes[0] & 0xff) == 100
                && (bytes[1] & 0xc0) == 64;
        return address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress() || uniqueLocalIpv6 || sharedIpv4;
    }
}
