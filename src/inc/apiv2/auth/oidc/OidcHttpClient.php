<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

/**
 * Minimal HTTP client for the OIDC provider. Tests substitute a fake.
 */
interface OidcHttpClient {
  /**
   * @return array<mixed> the decoded JSON object
   * @throws OidcException on transport failure, a non-2xx status or a non-JSON body
   */
  public function getJson(string $url): array;

  /**
   * @param array<string, string> $fields sent as application/x-www-form-urlencoded
   * @return array<mixed> the decoded JSON object
   * @throws OidcException on transport failure, a non-2xx status or a non-JSON body
   */
  public function postForm(string $url, array $fields): array;
}
