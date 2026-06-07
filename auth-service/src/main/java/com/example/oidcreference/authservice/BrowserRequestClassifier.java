package com.example.oidcreference.authservice;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

@Component
class BrowserRequestClassifier {
  boolean isDocumentNavigation(HttpServletRequest request) {
    String mode = request.getHeader("Sec-Fetch-Mode");
    String dest = request.getHeader("Sec-Fetch-Dest");
    if (mode != null || dest != null) {
      return "navigate".equalsIgnoreCase(mode) && "document".equalsIgnoreCase(dest);
    }
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains(MediaType.TEXT_HTML_VALUE);
  }
}
