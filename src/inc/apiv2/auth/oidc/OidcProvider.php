<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Hashtopolis\inc\StartupConfig;
use stdClass;
use Throwable;

/**
 * Talks to the configured OpenID Connect provider: discovery, JWKS, authorization URL, code exchange
 * and ID token validation. Every failure surfaces as OidcException, whose message never contains
 * token contents, the authorization code or the client secret.
 */
class OidcProvider {
  private const CACHE_TTL = 3600;
  private const LEEWAY = 60;
  /** Only these algorithms are accepted; the algorithm is taken from the JWK, never from the token. */
  private const ALLOWED_ALGS = ['RS256' => 'RSA', 'ES256' => 'EC'];

  /** @var array<mixed>|null */
  private ?array $discovery = null;

  public function __construct(
    private readonly OidcConfig $config,
    private readonly OidcHttpClient $http,
    private readonly string $cacheDir
  ) {
  }

  /**
   * Production wiring: cURL client and a cache directory below HASHTOPOLIS_CONFIG_PATH.
   */
  public static function fromConfig(OidcConfig $config): OidcProvider {
    $cacheDir = rtrim(StartupConfig::getInstance()->getDirectoryConfig(), '/') . '/oidc-cache';
    if (!is_dir($cacheDir)) {
      @mkdir($cacheDir, 0700, true);
    }
    if (!is_dir($cacheDir) || !is_writable($cacheDir)) {
      error_log("OIDC: cache directory " . $cacheDir . " is not writable, provider metadata will not be cached");
    }
    return new OidcProvider($config, new CurlOidcHttpClient($config->allowsInsecureHttp()), $cacheDir);
  }

  /**
   * @throws OidcException
   */
  public function authorizationUrl(string $state, string $nonce, string $codeChallenge): string {
    return $this->guard(function () use ($state, $nonce, $codeChallenge) {
      $endpoint = $this->endpoint('authorization_endpoint');
      $query = http_build_query([
        'response_type' => 'code',
        'client_id' => $this->config->getClientId(),
        'redirect_uri' => $this->config->getRedirectUri(),
        'scope' => $this->config->getScopes(),
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => 'S256',
      ], '', '&', PHP_QUERY_RFC3986);
      return $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . $query;
    });
  }

  /**
   * Exchanges the authorization code at the token endpoint (client_secret_post) and returns the raw ID token.
   *
   * @throws OidcException
   */
  public function exchangeCode(string $code, string $codeVerifier): string {
    return $this->guard(function () use ($code, $codeVerifier) {
      $response = $this->http->postForm($this->endpoint('token_endpoint'), [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $this->config->getRedirectUri(),
        'client_id' => $this->config->getClientId(),
        'client_secret' => $this->config->getClientSecret(),
        'code_verifier' => $codeVerifier,
      ]);
      if (!isset($response['id_token']) || !is_string($response['id_token']) || $response['id_token'] === '') {
        throw new OidcException("token endpoint response did not contain an id_token");
      }
      return $response['id_token'];
    });
  }

  /**
   * Verifies the ID token's signature and claims (spec §6) and returns the asserted identity.
   *
   * @throws OidcException
   */
  public function validateIdToken(string $idToken, string $nonce): OidcClaims {
    return $this->guard(function () use ($idToken, $nonce) {
      if ($nonce === '') {
        throw new OidcException("expected nonce is empty");
      }
      $key = $this->keyForToken($idToken);
      $payload = $this->decode($idToken, $key);
      return $this->checkClaims($payload, $nonce);
    });
  }

  /**
   * Runs $fn and converts anything that is not already an OidcException into one. The original message is
   * dropped on purpose, it might contain response or token data.
   *
   * @template T
   * @param callable(): T $fn
   * @return T
   * @throws OidcException
   */
  private function guard(callable $fn): mixed {
    try {
      return $fn();
    }
    catch (OidcException $e) {
      throw $e;
    }
    catch (Throwable $e) {
      throw new OidcException("OIDC provider error (" . get_class($e) . ")");
    }
  }

  private function now(): int {
    // JWT::$timestamp is php-jwt's clock override; using it here keeps one clock for tokens and cache.
    return JWT::$timestamp ?? time();
  }

  /**
   * @throws OidcException
   */
  private function endpoint(string $name): string {
    $discovery = $this->discovery();
    $url = $discovery[$name] ?? null;
    if (!is_string($url) || !$this->isAllowedUrl($url)) {
      throw new OidcException("discovery document has no usable " . $name);
    }
    return $url;
  }

  private function isAllowedUrl(string $url): bool {
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    $host = parse_url($url, PHP_URL_HOST);
    if (!is_string($host) || $host === '') {
      return false;
    }
    return $scheme === 'https' || ($scheme === 'http' && $this->config->allowsInsecureHttp());
  }

  /**
   * @return array<mixed>
   * @throws OidcException
   */
  private function discovery(): array {
    if ($this->discovery !== null) {
      return $this->discovery;
    }
    $doc = $this->readCache('discovery');
    if ($doc === null || !$this->issuerMatches($doc)) {
      $doc = $this->http->getJson(rtrim($this->config->getIssuer(), '/') . '/.well-known/openid-configuration');
      if (!$this->issuerMatches($doc)) {
        throw new OidcException("issuer mismatch: discovery document does not belong to the configured issuer");
      }
      $this->writeCache('discovery', $doc);
    }
    $this->discovery = $doc;
    return $doc;
  }

  /**
   * @param array<mixed> $doc
   */
  private function issuerMatches(array $doc): bool {
    return isset($doc['issuer']) && is_string($doc['issuer']) && $doc['issuer'] === $this->config->getIssuer();
  }

  /**
   * @return array<string, Key> usable signing keys by kid
   * @throws OidcException
   */
  private function signingKeys(bool $forceRefresh): array {
    $jwks = $forceRefresh ? null : $this->readCache('jwks');
    if ($jwks === null) {
      $jwks = $this->http->getJson($this->endpoint('jwks_uri'));
      $this->writeCache('jwks', $jwks);
    }
    return $this->parseKeys($jwks);
  }

  /**
   * Keeps only signature keys whose algorithm (from "alg", or derived from "kty" when "alg" is missing)
   * is RS256 or ES256 (P-256). Everything else, including keys php-jwt cannot parse, is dropped.
   *
   * @param array<mixed> $jwks
   * @return array<string, Key>
   */
  private function parseKeys(array $jwks): array {
    $keys = [];
    if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
      return $keys;
    }
    foreach ($jwks['keys'] as $jwk) {
      if (!is_array($jwk) || !isset($jwk['kid']) || !is_string($jwk['kid']) || !isset($jwk['kty']) || !is_string($jwk['kty'])) {
        continue;
      }
      if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
        continue;
      }
      $alg = $jwk['alg'] ?? match ($jwk['kty']) {
        'RSA' => 'RS256',
        'EC' => 'ES256',
        default => null,
      };
      if (!is_string($alg) || (self::ALLOWED_ALGS[$alg] ?? null) !== $jwk['kty']) {
        continue;
      }
      if ($alg === 'ES256' && ($jwk['crv'] ?? null) !== 'P-256') {
        continue;
      }
      $jwk['alg'] = $alg;
      try {
        $key = JWK::parseKey($jwk);
      }
      catch (Throwable) {
        continue;
      }
      if ($key !== null) {
        $keys[$jwk['kid']] = $key;
      }
    }
    return $keys;
  }

  /**
   * Looks up the key named by the token's kid. On an unknown kid the JWKS is refetched once, bypassing the cache.
   *
   * @throws OidcException
   */
  private function keyForToken(string $idToken): Key {
    $parts = explode('.', $idToken);
    if (count($parts) !== 3) {
      throw new OidcException("ID token is malformed");
    }
    $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
    if (!is_array($header) || !isset($header['kid']) || !is_string($header['kid']) || $header['kid'] === '') {
      throw new OidcException("ID token header has no key id");
    }
    $kid = $header['kid'];
    $keys = $this->signingKeys(false);
    if (!isset($keys[$kid])) {
      $keys = $this->signingKeys(true);
    }
    if (!isset($keys[$kid])) {
      throw new OidcException("ID token is signed with an unknown key");
    }
    return $keys[$kid];
  }

  /**
   * Verifies the signature (php-jwt rejects a header alg that differs from the key's alg) and exp/nbf
   * with the leeway, which is set for this call only.
   *
   * @throws OidcException
   */
  private function decode(string $idToken, Key $key): stdClass {
    $previousLeeway = JWT::$leeway;
    JWT::$leeway = self::LEEWAY;
    try {
      return JWT::decode($idToken, $key);
    }
    catch (SignatureInvalidException) {
      throw new OidcException("ID token signature verification failed");
    }
    catch (ExpiredException) {
      throw new OidcException("ID token has expired");
    }
    catch (BeforeValidException) {
      throw new OidcException("ID token is not yet valid");
    }
    catch (Throwable) {
      throw new OidcException("ID token is invalid");
    }
    finally {
      JWT::$leeway = $previousLeeway;
    }
  }

  /**
   * @throws OidcException
   */
  private function checkClaims(stdClass $payload, string $nonce): OidcClaims {
    $clientId = $this->config->getClientId();

    if (!isset($payload->iss) || !is_string($payload->iss) || $payload->iss !== $this->config->getIssuer()) {
      throw new OidcException("ID token issuer does not match");
    }

    $aud = $payload->aud ?? null;
    $audiences = is_string($aud) ? [$aud] : (is_array($aud) ? $aud : []);
    if (!in_array($clientId, $audiences, true)) {
      throw new OidcException("ID token audience does not contain the client id");
    }
    if (count($audiences) > 1 && !isset($payload->azp)) {
      throw new OidcException("ID token has several audiences but no azp");
    }
    if (isset($payload->azp) && $payload->azp !== $clientId) {
      throw new OidcException("ID token azp does not match the client id");
    }

    $now = $this->now();
    if (!isset($payload->exp) || !is_numeric($payload->exp)) {
      throw new OidcException("ID token has no exp");
    }
    // php-jwt has already rejected exp in the past (with leeway); iat is checked here because php-jwt
    // skips it when nbf is present and does not require it.
    if (!isset($payload->iat) || !is_numeric($payload->iat)) {
      throw new OidcException("ID token has no iat");
    }
    if (floor((float)$payload->iat) > $now + self::LEEWAY) {
      throw new OidcException("ID token iat is in the future");
    }

    if (!isset($payload->nonce) || !is_string($payload->nonce) || !hash_equals($nonce, $payload->nonce)) {
      throw new OidcException("ID token nonce does not match");
    }

    if (!isset($payload->sub) || !is_string($payload->sub) || $payload->sub === '') {
      throw new OidcException("ID token has no subject");
    }

    $label = $payload->sub;
    foreach (['preferred_username', 'email'] as $claim) {
      if (isset($payload->$claim) && is_string($payload->$claim) && $payload->$claim !== '') {
        $label = $payload->$claim;
        break;
      }
    }
    return new OidcClaims($payload->iss, $payload->sub, $label);
  }

  private function cacheFile(string $kind): string {
    return $this->cacheDir . '/' . $kind . '-' . hash('sha256', $this->config->getIssuer()) . '.json';
  }

  /**
   * @return array<mixed>|null the cached document, or null when missing, expired or corrupt
   */
  private function readCache(string $kind): ?array {
    $raw = @file_get_contents($this->cacheFile($kind));
    if ($raw === false) {
      return null;
    }
    $entry = json_decode($raw, true);
    if (!is_array($entry) || !isset($entry['fetchedAt']) || !is_int($entry['fetchedAt']) || !isset($entry['data']) || !is_array($entry['data'])) {
      return null;
    }
    $age = $this->now() - $entry['fetchedAt'];
    if ($age < 0 || $age >= self::CACHE_TTL) {
      return null;
    }
    return $entry['data'];
  }

  /**
   * Writes atomically (temp file + rename). A failed write only costs a refetch, so it is not an error.
   *
   * @param array<mixed> $data
   */
  private function writeCache(string $kind, array $data): void {
    $json = json_encode(['fetchedAt' => $this->now(), 'data' => $data]);
    if ($json === false) {
      return;
    }
    // tempnam silently falls back to the system temp dir when $cacheDir is unusable, so check first
    if (!is_dir($this->cacheDir) || !is_writable($this->cacheDir)) {
      return;
    }
    $tmp = @tempnam($this->cacheDir, 'oidc');
    if ($tmp === false) {
      return;
    }
    if (@file_put_contents($tmp, $json) === false || !@rename($tmp, $this->cacheFile($kind))) {
      @unlink($tmp);
    }
  }
}
