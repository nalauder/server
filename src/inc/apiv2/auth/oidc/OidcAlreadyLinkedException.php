<?php

namespace Hashtopolis\inc\apiv2\auth\oidc;

use Hashtopolis\inc\HTException;

/**
 * Thrown when an OIDC identity is already linked to a different user.
 */
class OidcAlreadyLinkedException extends HTException {
  // nothing
}
