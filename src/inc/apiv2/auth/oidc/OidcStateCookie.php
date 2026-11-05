<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\inc\apiv2\auth\RefreshTokenCookie;
use Hashtopolis\inc\StartupConfig;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Carries the OIDC state value from the redirect to the provider back to the callback, so the
 * callback can tell it answers a login this browser started.
 *
 * SameSite is Lax rather than Strict because the callback is a top-level navigation arriving from the
 * provider's site, which Strict would withhold the cookie from. It follows the refresh cookie into
 * None only when that is configured, as a frontend on another site needs the same for both.
 */
class OidcStateCookie {
  const COOKIE_NAME = "oidcState";
  const COOKIE_PATH = "/api/v2/auth/oidc";
  const MAX_AGE = 600;
  
  /**
   * @return string|null the state sent by the client, or null when absent or not 64 lowercase hex characters
   */
  public static function read(Request $request): ?string {
    $cookies = $request->getCookieParams();
    if (!isset($cookies[self::COOKIE_NAME]) || !is_string($cookies[self::COOKIE_NAME])) {
      return null;
    }
    $value = $cookies[self::COOKIE_NAME];
    
    return preg_match('/^[0-9a-f]{64}$/D', $value) === 1 ? $value : null;
  }
  
  /**
   * Sets the state cookie on the response.
   *
   * @param Request $request the request being answered, used to decide on the Secure flag
   * @param Response $response
   * @param string $state the state value sent to the provider
   * @return Response
   */
  public static function attach(Request $request, Response $response, string $state): Response {
    return $response->withAddedHeader("Set-Cookie", self::build($request, $state, self::MAX_AGE));
  }
  
  /**
   * The attributes match those used when the cookie was set, otherwise the browser keeps it.
   */
  public static function clear(Request $request, Response $response): Response {
    return $response->withAddedHeader("Set-Cookie", self::build($request, "", 0));
  }
  
  /**
   * @param Request $request
   * @param string $value the state, or an empty string when clearing
   * @param int $maxAge lifetime in seconds, 0 to expire the cookie
   * @return string the Set-Cookie header value
   */
  private static function build(Request $request, string $value, int $maxAge): string {
    $sameSite = StartupConfig::getInstance()->getRefreshCookieSameSite() === "None" ? "None" : "Lax";
    
    $parts = [
      self::COOKIE_NAME . "=" . $value,
      "Path=" . self::COOKIE_PATH,
      "Max-Age=" . $maxAge,
      "Expires=" . gmdate("D, d M Y H:i:s \G\M\T", time() + $maxAge),
      "HttpOnly",
      "SameSite=" . $sameSite,
    ];
    if (RefreshTokenCookie::secureFlag($request, $sameSite)) {
      $parts[] = "Secure";
    }
    
    return implode("; ", $parts);
  }
}
