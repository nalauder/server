<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use JsonException;

/**
 * OidcHttpClient on top of cURL. HTTPS only (plain HTTP only when explicitly allowed for development),
 * TLS verification on, 10 s timeouts, no redirects.
 */
final class CurlOidcHttpClient implements OidcHttpClient {
  private const TIMEOUT_SECONDS = 10;

  public function __construct(private readonly bool $allowInsecureHttp) {
  }

  public function getJson(string $url): array {
    return $this->request($url, null);
  }

  public function postForm(string $url, array $fields): array {
    return $this->request($url, $fields);
  }

  /**
   * @param array<string, string>|null $fields POST body, or null for GET
   * @return array<mixed>
   * @throws OidcException
   */
  private function request(string $url, ?array $fields): array {
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if ($scheme !== 'https' && !($scheme === 'http' && $this->allowInsecureHttp)) {
      throw new OidcException("refusing non-https provider URL: " . $url);
    }
    $protocols = $this->allowInsecureHttp ? 'http,https' : 'https';

    $ch = curl_init();
    curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_CONNECTTIMEOUT => self::TIMEOUT_SECONDS,
      CURLOPT_TIMEOUT => self::TIMEOUT_SECONDS,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_PROTOCOLS_STR => $protocols,
      CURLOPT_REDIR_PROTOCOLS_STR => $protocols,
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);
    if ($fields !== null) {
      curl_setopt($ch, CURLOPT_POST, true);
      curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($fields, '', '&', PHP_QUERY_RFC1738));
    }
    $body = curl_exec($ch);
    if (!is_string($body)) {
      throw new OidcException("request to " . $url . " failed: " . curl_error($ch));
    }
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    if ($status < 200 || $status > 299) {
      throw new OidcException("request to " . $url . " returned HTTP " . $status);
    }
    try {
      $json = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
    }
    catch (JsonException) {
      throw new OidcException("response from " . $url . " is not valid JSON");
    }
    if (!is_array($json) || array_is_list($json) && $json !== []) {
      throw new OidcException("response from " . $url . " is not a JSON object");
    }
    return $json;
  }
}
