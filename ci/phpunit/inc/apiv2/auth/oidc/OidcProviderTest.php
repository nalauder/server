<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use RuntimeException;

require_once(dirname(__FILE__) . '/../../../../../../src/inc/startup/include.php');

/**
 * In-memory OidcHttpClient that serves canned JSON per URL and records every call.
 */
final class FakeOidcHttpClient implements OidcHttpClient {
  /** @var array<string, array<mixed>> */
  public array $responses = [];
  /** @var list<array{method: string, url: string, fields: array<string, string>}> */
  public array $calls = [];
  public ?\Throwable $throw = null;

  public function getJson(string $url): array {
    $this->calls[] = ['method' => 'GET', 'url' => $url, 'fields' => []];
    return $this->respond($url);
  }

  public function postForm(string $url, array $fields): array {
    $this->calls[] = ['method' => 'POST', 'url' => $url, 'fields' => $fields];
    return $this->respond($url);
  }

  /**
   * @return array<mixed>
   */
  private function respond(string $url): array {
    if ($this->throw !== null) {
      throw $this->throw;
    }
    if (!isset($this->responses[$url])) {
      throw new OidcException("no canned response");
    }
    return $this->responses[$url];
  }

  public function count(string $url): int {
    return count(array_filter($this->calls, fn($c) => $c['url'] === $url));
  }
}

final class OidcProviderTest extends TestCase {
  private const ISSUER = 'https://idp.example.test/realms/test';
  private const CLIENT_ID = 'hashtopolis';
  private const SECRET = 'test-client-secret';
  private const DISCOVERY = self::ISSUER . '/.well-known/openid-configuration';
  private const AUTH = self::ISSUER . '/protocol/openid-connect/auth';
  private const TOKEN = self::ISSUER . '/protocol/openid-connect/token';
  private const JWKS = self::ISSUER . '/protocol/openid-connect/certs';
  private const NOW = 1_900_000_000;

  private static ?\OpenSSLAsymmetricKey $rsaKey = null;
  private static ?\OpenSSLAsymmetricKey $rsaKey2 = null;
  private \OpenSSLAsymmetricKey $ecKey;
  private FakeOidcHttpClient $http;
  private string $cacheDir;

  protected function setUp(): void {
    // RSA generation is slow, so the two RSA keys are shared across tests.
    if (self::$rsaKey === null) {
      self::$rsaKey = $this->newKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
      self::$rsaKey2 = $this->newKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    }
    $this->ecKey = $this->newKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

    JWT::$timestamp = self::NOW;
    $this->cacheDir = sys_get_temp_dir() . '/oidc-provider-test-' . bin2hex(random_bytes(6));
    mkdir($this->cacheDir, 0700);

    $this->http = new FakeOidcHttpClient();
    $this->http->responses[self::DISCOVERY] = [
      'issuer' => self::ISSUER,
      'authorization_endpoint' => self::AUTH,
      'token_endpoint' => self::TOKEN,
      'jwks_uri' => self::JWKS,
    ];
    $this->http->responses[self::JWKS] = ['keys' => [
      $this->rsaJwk(self::$rsaKey, 'rsa-1'),
      $this->ecJwk($this->ecKey, 'ec-1'),
    ]];
  }

  protected function tearDown(): void {
    JWT::$timestamp = null;
    foreach (glob($this->cacheDir . '/*') ?: [] as $f) {
      unlink($f);
    }
    rmdir($this->cacheDir);
  }

  /**
   * @param array<string, mixed> $options
   */
  private function newKey(array $options): \OpenSSLAsymmetricKey {
    $key = openssl_pkey_new($options);
    if ($key === false) {
      throw new RuntimeException("openssl_pkey_new failed");
    }
    return $key;
  }

  private static function b64u(string $raw): string {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
  }

  /**
   * @return array<string, string>
   */
  private function rsaJwk(\OpenSSLAsymmetricKey $key, string $kid): array {
    $d = openssl_pkey_get_details($key);
    return ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256',
      'n' => self::b64u($d['rsa']['n']), 'e' => self::b64u($d['rsa']['e'])];
  }

  /**
   * @return array<string, string>
   */
  private function ecJwk(\OpenSSLAsymmetricKey $key, string $kid): array {
    $d = openssl_pkey_get_details($key);
    $this->assertSame('prime256v1', $d['ec']['curve_name']);
    return ['kty' => 'EC', 'kid' => $kid, 'use' => 'sig', 'crv' => 'P-256',
      'x' => self::b64u(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)),
      'y' => self::b64u(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT))];
  }

  private function provider(?OidcConfig $config = null): OidcProvider {
    $config ??= new OidcConfig([
      'HASHTOPOLIS_OIDC_ISSUER' => self::ISSUER,
      'HASHTOPOLIS_OIDC_CLIENT_ID' => self::CLIENT_ID,
      'HASHTOPOLIS_OIDC_CLIENT_SECRET' => self::SECRET,
      'HASHTOPOLIS_BACKEND_URL' => 'https://hashtopolis.example.test/api/v2',
    ]);
    return new OidcProvider($config, $this->http, $this->cacheDir);
  }

  /**
   * @param array<string, mixed> $overrides null values remove the claim
   * @return array<string, mixed>
   */
  private function claims(array $overrides = []): array {
    $claims = array_merge([
      'iss' => self::ISSUER,
      'sub' => 'subject-123',
      'aud' => self::CLIENT_ID,
      'exp' => self::NOW + 300,
      'iat' => self::NOW,
      'nonce' => 'the-nonce',
      'preferred_username' => 'alice',
      'email' => 'alice@example.test',
    ], $overrides);
    return array_filter($claims, fn($v) => $v !== null);
  }

  /**
   * @param array<string, mixed> $overrides
   */
  private function rsToken(array $overrides = [], string $kid = 'rsa-1', ?\OpenSSLAsymmetricKey $key = null): string {
    return JWT::encode($this->claims($overrides), $key ?? self::$rsaKey, 'RS256', $kid);
  }

  private function assertRejected(string $token, string $expectedMessage, string $nonce = 'the-nonce'): void {
    try {
      $this->provider()->validateIdToken($token, $nonce);
      $this->fail("token was accepted");
    }
    catch (OidcException $e) {
      $this->assertStringContainsString($expectedMessage, $e->getMessage());
      $this->assertStringNotContainsString($token, $e->getMessage());
      $this->assertStringNotContainsString('alice', $e->getMessage());
    }
  }

  public function testDiscoveryIssuerMismatchThrows(): void {
    $this->http->responses[self::DISCOVERY]['issuer'] = 'https://evil.example.test/realms/test';
    $this->expectException(OidcException::class);
    $this->expectExceptionMessage('issuer mismatch');
    $this->provider()->authorizationUrl('s', 'n', 'c');
  }

  public function testAuthorizationUrlParams(): void {
    $url = $this->provider()->authorizationUrl('the-state', 'the-nonce', 'the-challenge');
    $this->assertStringStartsWith(self::AUTH . '?', $url);
    parse_str((string)parse_url($url, PHP_URL_QUERY), $q);
    $this->assertSame('code', $q['response_type']);
    $this->assertSame(self::CLIENT_ID, $q['client_id']);
    $this->assertSame('https://hashtopolis.example.test/api/v2/auth/oidc/callback', $q['redirect_uri']);
    $this->assertSame('openid profile email', $q['scope']);
    $this->assertSame('the-state', $q['state']);
    $this->assertSame('the-nonce', $q['nonce']);
    $this->assertSame('the-challenge', $q['code_challenge']);
    $this->assertSame('S256', $q['code_challenge_method']);
    $this->assertArrayNotHasKey('response_mode', $q);
    $this->assertStringNotContainsString(self::SECRET, $url);
  }

  public function testExchangeCodeSendsVerifierAndSecret(): void {
    $this->http->responses[self::TOKEN] = ['id_token' => 'the.id.token', 'access_token' => 'x'];
    $idToken = $this->provider()->exchangeCode('the-code', 'the-verifier');
    $this->assertSame('the.id.token', $idToken);
    $post = array_values(array_filter($this->http->calls, fn($c) => $c['method'] === 'POST'));
    $this->assertCount(1, $post);
    $this->assertSame(self::TOKEN, $post[0]['url']);
    $this->assertSame([
      'grant_type' => 'authorization_code',
      'code' => 'the-code',
      'redirect_uri' => 'https://hashtopolis.example.test/api/v2/auth/oidc/callback',
      'client_id' => self::CLIENT_ID,
      'client_secret' => self::SECRET,
      'code_verifier' => 'the-verifier',
    ], $post[0]['fields']);
  }

  public function testExchangeCodeMissingIdTokenThrows(): void {
    $this->http->responses[self::TOKEN] = ['access_token' => 'x'];
    $this->expectException(OidcException::class);
    $this->provider()->exchangeCode('the-code', 'the-verifier');
  }

  public function testValidTokenRs256(): void {
    $claims = $this->provider()->validateIdToken($this->rsToken(), 'the-nonce');
    $this->assertSame(self::ISSUER, $claims->issuer);
    $this->assertSame('subject-123', $claims->subject);
    $this->assertSame('alice', $claims->label);
  }

  public function testValidTokenEs256(): void {
    $token = JWT::encode($this->claims(), $this->ecKey, 'ES256', 'ec-1');
    $claims = $this->provider()->validateIdToken($token, 'the-nonce');
    $this->assertSame('subject-123', $claims->subject);
  }

  public function testWrongSignature(): void {
    // Signed with a key that is not in the JWKS, but claiming the published kid.
    $this->assertRejected($this->rsToken([], 'rsa-1', self::$rsaKey2), 'signature verification failed');
  }

  public function testWrongIssuer(): void {
    $this->assertRejected($this->rsToken(['iss' => 'https://evil.example.test/realms/test']), 'issuer does not match');
  }

  public function testWrongAudience(): void {
    $this->assertRejected($this->rsToken(['aud' => 'other-client']), 'audience does not contain');
    $this->assertRejected($this->rsToken(['aud' => ['other-client']]), 'audience does not contain');
  }

  public function testMultiAudienceRequiresAzp(): void {
    $this->assertRejected($this->rsToken(['aud' => [self::CLIENT_ID, 'other']]), 'several audiences but no azp');
    $this->assertRejected($this->rsToken(['aud' => [self::CLIENT_ID, 'other'], 'azp' => 'other']), 'azp does not match');
    $this->assertRejected($this->rsToken(['aud' => self::CLIENT_ID, 'azp' => 'other']), 'azp does not match');
    $claims = $this->provider()->validateIdToken(
      $this->rsToken(['aud' => [self::CLIENT_ID, 'other'], 'azp' => self::CLIENT_ID]), 'the-nonce');
    $this->assertSame('subject-123', $claims->subject);
  }

  public function testWrongNonce(): void {
    $this->assertRejected($this->rsToken(), 'nonce does not match', 'another-nonce');
  }

  public function testEmptyExpectedNonceRejected(): void {
    $this->assertRejected($this->rsToken(['nonce' => '']), 'expected nonce is empty', '');
  }

  public function testIssuerWithTrailingSlashKeptExact(): void {
    $issuer = 'https://idp.example.test/tenant/';
    $discovery = 'https://idp.example.test/tenant/.well-known/openid-configuration';
    $this->http->responses = [
      $discovery => array_merge($this->http->responses[self::DISCOVERY], ['issuer' => $issuer]),
      self::JWKS => $this->http->responses[self::JWKS],
    ];
    $provider = $this->provider(new OidcConfig([
      'HASHTOPOLIS_OIDC_ISSUER' => $issuer,
      'HASHTOPOLIS_OIDC_CLIENT_ID' => self::CLIENT_ID,
      'HASHTOPOLIS_OIDC_CLIENT_SECRET' => self::SECRET,
    ]));
    $claims = $provider->validateIdToken($this->rsToken(['iss' => $issuer]), 'the-nonce');
    $this->assertSame($issuer, $claims->issuer);
    $this->assertSame(1, $this->http->count($discovery));
    // The slash-less form is a different issuer and is rejected.
    $this->expectException(OidcException::class);
    $this->expectExceptionMessage('issuer does not match');
    $provider->validateIdToken($this->rsToken(['iss' => rtrim($issuer, '/')]), 'the-nonce');
  }

  public function testMissingNonce(): void {
    $this->assertRejected($this->rsToken(['nonce' => null]), 'nonce does not match');
  }

  public function testMissingSubOrExpOrIatRejected(): void {
    $this->assertRejected($this->rsToken(['sub' => null]), 'no subject');
    $this->assertRejected($this->rsToken(['sub' => '']), 'no subject');
    $this->assertRejected($this->rsToken(['exp' => null]), 'has no exp');
    $this->assertRejected($this->rsToken(['iat' => null]), 'has no iat');
  }

  public function testLeewayOnlySetDuringDecode(): void {
    $this->assertSame(0, JWT::$leeway);
    $this->provider()->validateIdToken($this->rsToken(), 'the-nonce');
    $this->assertSame(0, JWT::$leeway);
    $this->assertRejected($this->rsToken([], 'rsa-1', self::$rsaKey2), 'signature verification failed');
    $this->assertSame(0, JWT::$leeway);
  }

  public function testAlgNoneRejected(): void {
    $header = self::b64u((string)json_encode(['typ' => 'JWT', 'alg' => 'none', 'kid' => 'rsa-1']));
    $body = self::b64u((string)json_encode($this->claims()));
    $this->assertRejected("$header.$body.", 'ID token is invalid');
  }

  public function testHs256WithPublicKeyAsSecretRejected(): void {
    $pem = openssl_pkey_get_details(self::$rsaKey)['key'];
    $this->assertRejected(JWT::encode($this->claims(), $pem, 'HS256', 'rsa-1'), 'ID token is invalid');
  }

  public function testExpiredBeyondLeewayRejected(): void {
    $this->assertRejected($this->rsToken(['iat' => self::NOW - 600, 'exp' => self::NOW - 61]), 'has expired');
    // Within leeway is still accepted.
    $claims = $this->provider()->validateIdToken($this->rsToken(['iat' => self::NOW - 600, 'exp' => self::NOW - 59]), 'the-nonce');
    $this->assertSame('subject-123', $claims->subject);
  }

  public function testIatWithin60sFutureAccepted(): void {
    $claims = $this->provider()->validateIdToken($this->rsToken(['iat' => self::NOW + 60]), 'the-nonce');
    $this->assertSame('subject-123', $claims->subject);
  }

  public function testIat61sFutureRejected(): void {
    $this->assertRejected($this->rsToken(['iat' => self::NOW + 61]), 'not yet valid');
    // An nbf claim must not switch off the iat check (php-jwt skips iat when nbf is set).
    $this->assertRejected($this->rsToken(['iat' => self::NOW + 61, 'nbf' => self::NOW]), 'iat is in the future');
  }

  public function testUnknownKidRefetchesOnceThenValidates(): void {
    $provider = $this->provider();
    $provider->validateIdToken($this->rsToken(), 'the-nonce');
    $this->assertSame(1, $this->http->count(self::JWKS));

    // The provider rotates keys; the cached JWKS does not know rsa-2 yet.
    $this->http->responses[self::JWKS] = ['keys' => [$this->rsaJwk(self::$rsaKey2, 'rsa-2')]];
    $claims = $this->provider()->validateIdToken($this->rsToken([], 'rsa-2', self::$rsaKey2), 'the-nonce');
    $this->assertSame('subject-123', $claims->subject);
    $this->assertSame(2, $this->http->count(self::JWKS));

    // The refetched set was cached, so the next validation needs no fetch.
    $this->provider()->validateIdToken($this->rsToken([], 'rsa-2', self::$rsaKey2), 'the-nonce');
    $this->assertSame(2, $this->http->count(self::JWKS));
  }

  public function testUnknownKidAfterRefetchThrows(): void {
    $this->provider()->validateIdToken($this->rsToken(), 'the-nonce');
    $this->assertSame(1, $this->http->count(self::JWKS));
    $this->assertRejected($this->rsToken([], 'unknown-kid', self::$rsaKey2), 'unknown key');
    $this->assertSame(2, $this->http->count(self::JWKS));
  }

  public function testJwksFiltersUnusableKeys(): void {
    $this->http->responses[self::JWKS] = ['keys' => [
      array_merge($this->rsaJwk(self::$rsaKey, 'enc-key'), ['use' => 'enc']),
      array_merge($this->rsaJwk(self::$rsaKey, 'rs512-key'), ['alg' => 'RS512']),
      ['kty' => 'oct', 'kid' => 'hmac-key', 'alg' => 'HS256', 'k' => self::b64u(str_repeat('s', 32))],
      array_diff_key($this->rsaJwk(self::$rsaKey, 'no-alg'), ['alg' => true]),
    ]];
    $this->assertRejected($this->rsToken([], 'enc-key'), 'unknown key');
    $this->assertRejected(JWT::encode($this->claims(), self::$rsaKey, 'RS512', 'rs512-key'), 'unknown key');
    $this->assertRejected(JWT::encode($this->claims(), str_repeat('s', 32), 'HS256', 'hmac-key'), 'unknown key');
    // An RSA key without alg maps to RS256.
    $claims = $this->provider()->validateIdToken($this->rsToken([], 'no-alg'), 'the-nonce');
    $this->assertSame('subject-123', $claims->subject);
  }

  public function testTransportFailureThrowsOidcException(): void {
    $this->http->throw = new RuntimeException("connection refused");
    try {
      $this->provider()->authorizationUrl('s', 'n', 'c');
      $this->fail("no exception");
    }
    catch (OidcException $e) {
      $this->assertNotSame('', $e->getMessage());
    }
    $this->http->throw = new \TypeError("bad type");
    $this->expectException(OidcException::class);
    $this->provider()->exchangeCode('the-code', 'the-verifier');
  }

  public function testCurlClientRejectsPlainHttpUnlessAllowed(): void {
    // Rejected before any request is made, so no network is needed.
    foreach (['http://idp.example.test/x', 'ftp://idp.example.test/x', 'file:///etc/passwd'] as $url) {
      try {
        (new CurlOidcHttpClient(false))->getJson($url);
        $this->fail("accepted " . $url);
      }
      catch (OidcException $e) {
        $this->assertStringContainsString('non-https', $e->getMessage());
      }
    }
    $this->expectException(OidcException::class);
    $this->expectExceptionMessage('non-https');
    (new CurlOidcHttpClient(true))->postForm('file:///etc/passwd', []);
  }

  public function testGarbageTokenThrowsOidcException(): void {
    $this->assertRejected('not-a-jwt', 'malformed');
    $this->assertRejected('a.b.c', 'no key id');
  }

  public function testLabelFallbacks(): void {
    $claims = $this->provider()->validateIdToken($this->rsToken(['preferred_username' => null]), 'the-nonce');
    $this->assertSame('alice@example.test', $claims->label);
    $claims = $this->provider()->validateIdToken($this->rsToken(['preferred_username' => null, 'email' => null]), 'the-nonce');
    $this->assertSame('subject-123', $claims->label);
    $claims = $this->provider()->validateIdToken($this->rsToken(['preferred_username' => '', 'email' => '']), 'the-nonce');
    $this->assertSame('subject-123', $claims->label);
  }

  public function testCacheReusedWithinTtl(): void {
    $this->provider()->validateIdToken($this->rsToken(), 'the-nonce');
    $this->provider()->validateIdToken($this->rsToken(), 'the-nonce');
    $this->provider()->authorizationUrl('s', 'n', 'c');
    $this->assertSame(1, $this->http->count(self::DISCOVERY));
    $this->assertSame(1, $this->http->count(self::JWKS));

    // After the TTL both documents are fetched again.
    JWT::$timestamp = self::NOW + 3601;
    $this->provider()->validateIdToken($this->rsToken(['iat' => self::NOW + 3601, 'exp' => self::NOW + 4000]), 'the-nonce');
    $this->assertSame(2, $this->http->count(self::DISCOVERY));
    $this->assertSame(2, $this->http->count(self::JWKS));
  }

  public function testCorruptCacheIsAMiss(): void {
    $this->provider()->authorizationUrl('s', 'n', 'c');
    foreach (glob($this->cacheDir . '/*') ?: [] as $f) {
      file_put_contents($f, '{not json');
    }
    $this->provider()->authorizationUrl('s', 'n', 'c');
    $this->assertSame(2, $this->http->count(self::DISCOVERY));
  }
}
