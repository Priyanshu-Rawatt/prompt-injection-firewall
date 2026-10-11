package com.et.hackathon.firewall.service.parser;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class ContentExtractionException extends RuntimeException {
    public ContentExtractionException(String message) {
        super(message);
    }

    public ContentExtractionException(String message, Throwable cause) {
        super(message, cause);
    }
}
