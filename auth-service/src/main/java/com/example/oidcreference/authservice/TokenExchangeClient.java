package com.example.oidcreference.authservice;

interface TokenExchangeClient {
  SessionRecord exchange(String code, String state, String redirectUri, OAuthTransaction transaction);
}
