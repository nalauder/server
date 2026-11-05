<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

/**
 * The identity asserted by a verified ID token. The pair (issuer, subject) is the only thing that
 * identifies a person; the label is for display and is never used to match an account.
 */
final readonly class OidcClaims {
  public function __construct(
    public string $issuer,
    public string $subject,
    public string $label
  ) {
  }
}
