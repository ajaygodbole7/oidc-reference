package com.example.oidcreference.authservice;

interface TokenRefreshClient {
  SessionRecord refresh(SessionRecord session);
}
