<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use JsonException;

/**
 * OidcHttpClient on top of cURL. HTTPS only (plain HTTP only when explicitly allowed for development),
 * TLS verification on, 10 s timeouts, no redirects.
 */
final class CurlOidcHttpClient implements OidcHttpClient {
  private const TIMEOUT_SECONDS = 10;

  /**
   * @param bool $allowInsecureHttp whether plain http:// URLs are accepted besides https://; for development against a local provider only
   */
  public function __construct(private readonly bool $allowInsecureHttp) {
  }

  /**
   * Fetches a URL with GET.
   *
   * @param string $url
   * @return array<mixed> the decoded JSON object
   * @throws OidcException on a refused URL, transport failure, non-2xx status or a body that is not a JSON object
   */
  public function getJson(string $url): array {
    return $this->request($url, null);
  }

  /**
   * Posts form fields (application/x-www-form-urlencoded) to a URL.
   *
   * @param string $url
   * @param array<string, string> $fields
   * @return array<mixed> the decoded JSON object
   * @throws OidcException on a refused URL, transport failure, non-2xx status or a body that is not a JSON object
   */
  public function postForm(string $url, array $fields): array {
    return $this->request($url, $fields);
  }

  /**
   * Performs the request. The URL scheme is checked before anything is sent, so a refused URL costs no
   * network access.
   *
   * @param string $url
   * @param array<string, string>|null $fields POST body, or null for GET
   * @return array<mixed>
   * @throws OidcException
   */
  private function request(string $url, ?array $fields): array {
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if ($scheme !== 'https' && !($scheme === 'http' && $this->allowInsecureHttp)) {
      throw new OidcException("refusing non-https provider URL: " . $url);
    }
    $protocols = $this->allowInsecureHttp ? (CURLPROTO_HTTPS | CURLPROTO_HTTP) : CURLPROTO_HTTPS;

    $ch = curl_init();
    curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_CONNECTTIMEOUT => self::TIMEOUT_SECONDS,
      CURLOPT_TIMEOUT => self::TIMEOUT_SECONDS,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_PROTOCOLS => $protocols,
      CURLOPT_REDIR_PROTOCOLS => $protocols,
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
