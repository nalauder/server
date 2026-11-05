<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\inc\apiv2\error\HttpForbidden;

/**
 * OIDC single sign-on settings, read from HASHTOPOLIS_* environment variables.
 * Empty strings count as unset.
 */
final class OidcConfig {
  private static ?OidcConfig $instance = null;

  /** @var array<string, string> */
  private array $settings = [];
  private bool $loggedIncomplete = false;
  private bool $loggedLocalLoginIgnored = false;

  /**
   * @param array<string, string> $settings keyed by environment variable name
   */
  public function __construct(array $settings) {
    foreach ($settings as $name => $value) {
      $value = trim((string)$value);
      if ($value !== "") {
        $this->settings[$name] = $value;
      }
    }
  }

  public static function fromEnvironment(): OidcConfig {
    $names = [
      'HASHTOPOLIS_OIDC_ISSUER',
      'HASHTOPOLIS_OIDC_CLIENT_ID',
      'HASHTOPOLIS_OIDC_CLIENT_SECRET',
      'HASHTOPOLIS_OIDC_SCOPES',
      'HASHTOPOLIS_OIDC_DISPLAY_NAME',
      'HASHTOPOLIS_LOCAL_LOGIN_ENABLED',
      'HASHTOPOLIS_OIDC_ALLOW_INSECURE_HTTP',
      'HASHTOPOLIS_BACKEND_URL',
    ];
    $settings = [];
    foreach ($names as $name) {
      $value = getenv($name);
      if ($value !== false) {
        $settings[$name] = $value;
      }
    }
    return new OidcConfig($settings);
  }

  public static function get(): OidcConfig {
    if (self::$instance === null) {
      self::$instance = self::fromEnvironment();
    }
    return self::$instance;
  }

  public static function setInstance(?OidcConfig $c): void {
    self::$instance = $c;
  }

  private function value(string $name, string $default = ""): string {
    return $this->settings[$name] ?? $default;
  }

  public function isEnabled(): bool {
    if ($this->value('HASHTOPOLIS_OIDC_ISSUER') === "") {
      return false;
    }
    if ($this->value('HASHTOPOLIS_OIDC_CLIENT_ID') === "" || $this->value('HASHTOPOLIS_OIDC_CLIENT_SECRET') === "") {
      if (!$this->loggedIncomplete) {
        $this->loggedIncomplete = true;
        error_log("OIDC: HASHTOPOLIS_OIDC_ISSUER is set but HASHTOPOLIS_OIDC_CLIENT_ID or HASHTOPOLIS_OIDC_CLIENT_SECRET is missing, single sign-on is disabled");
      }
      return false;
    }
    return true;
  }

  public function isLocalLoginEnabled(): bool {
    $setting = strtolower($this->value('HASHTOPOLIS_LOCAL_LOGIN_ENABLED'));
    if ($setting !== "false" && $setting !== "0") {
      return true;
    }
    if (!$this->isEnabled()) {
      if (!$this->loggedLocalLoginIgnored) {
        $this->loggedLocalLoginIgnored = true;
        error_log("OIDC: HASHTOPOLIS_LOCAL_LOGIN_ENABLED disables password login but single sign-on is not configured, keeping password login enabled");
      }
      return true;
    }
    return false;
  }

  public function getIssuer(): string {
    // Kept exactly as configured (whitespace aside): some issuers end in "/" and iss is compared exactly.
    return $this->value('HASHTOPOLIS_OIDC_ISSUER');
  }

  public function getClientId(): string {
    return $this->value('HASHTOPOLIS_OIDC_CLIENT_ID');
  }

  public function getClientSecret(): string {
    return $this->value('HASHTOPOLIS_OIDC_CLIENT_SECRET');
  }

  public function getScopes(): string {
    return $this->value('HASHTOPOLIS_OIDC_SCOPES', 'openid profile email');
  }

  public function getDisplayName(): string {
    return $this->value('HASHTOPOLIS_OIDC_DISPLAY_NAME', 'SSO');
  }

  public function allowsInsecureHttp(): bool {
    return strtolower($this->value('HASHTOPOLIS_OIDC_ALLOW_INSECURE_HTTP')) === "true";
  }

  public function getRedirectUri(): string {
    return rtrim($this->value('HASHTOPOLIS_BACKEND_URL'), '/') . '/auth/oidc/callback';
  }

  /**
   * @throws HttpForbidden
   */
  public function assertLocalLoginAllowed(): void {
    if (!$this->isLocalLoginEnabled()) {
      throw new HttpForbidden("Password login is disabled on this server. Use single sign-on.");
    }
  }
}
