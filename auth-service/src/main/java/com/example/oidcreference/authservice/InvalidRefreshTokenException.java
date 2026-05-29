package com.example.oidcreference.authservice;

class InvalidRefreshTokenException extends RuntimeException {
  InvalidRefreshTokenException(String message) {
    super(message);
  }
}
