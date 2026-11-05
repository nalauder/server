<?php

use Hashtopolis\inc\apiv2\auth\oidc\OidcConfig;
use Hashtopolis\inc\apiv2\auth\oidc\OidcController;
use Hashtopolis\inc\apiv2\auth\oidc\OidcProvider;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\App;
use Slim\Routing\RouteCollectorProxy;

require_once(dirname(__FILE__) . "/../../startup/include.php");

/*
 * OpenID Connect single sign-on, spec §7. The handlers live in OidcController; config, login and
 * callback are public (see the JWT ignore list in api/v2/index.php), the rest need an access token.
 */

function oidcController(): OidcController {
  $config = OidcConfig::get();
  return new OidcController($config, OidcProvider::fromConfig($config));
}

/** @var App $app */
$app->group("/api/v2/auth/oidc", function (RouteCollectorProxy $group) {
  /* Allow preflight requests */
  $group->options('/{path:.*}', function (Request $request, Response $response): Response {
    return $response;
  });

  $group->get('/config', function (Request $request, Response $response): Response {
    return oidcController()->config($request, $response);
  });

  $group->get('/login', function (Request $request, Response $response): Response {
    return oidcController()->login($request, $response);
  });

  $group->get('/callback', function (Request $request, Response $response): Response {
    return oidcController()->callback($request, $response);
  });

  $group->post('/link-pending', function (Request $request, Response $response): Response {
    return oidcController()->linkPending($request, $response);
  });

  $group->post('/link', function (Request $request, Response $response): Response {
    return oidcController()->link($request, $response);
  });

  $group->get('/identities', function (Request $request, Response $response): Response {
    return oidcController()->listIdentities($request, $response);
  });

  $group->delete('/identities/{id:[0-9]+}', function (Request $request, Response $response, array $args): Response {
    return oidcController()->unlinkIdentity($request, $response, (int)$args['id']);
  });
});
