<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\inc\HTException;

/**
 * Any failure while talking to the OIDC provider or validating its ID token.
 * Messages never contain tokens, codes or the client secret.
 */
class OidcException extends HTException {
  // nothing
}
