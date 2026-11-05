<?php

namespace Hashtopolis\inc\handlers;

use Throwable;
use Hashtopolis\inc\apiv2\auth\oidc\OidcConfig;
use Hashtopolis\inc\defines\DForgotAction;
use Hashtopolis\inc\UI;
use Hashtopolis\inc\utils\UserUtils;

class ForgotHandler implements Handler {
  public const LOCAL_LOGIN_DISABLED_MESSAGE = "Password reset is disabled on this server. Use single sign-on.";
  
  public function __construct($configId = null) {
    //we need nothing to load
  }
  
  public function handle($action): void {
    try {
      switch ($action) {
        case DForgotAction::RESET:
          // Checked before the user lookup, so the answer does not reveal whether the user exists
          if (!OidcConfig::get()->isLocalLoginEnabled()) {
            UI::addMessage(UI::ERROR, self::LOCAL_LOGIN_DISABLED_MESSAGE);
            break;
          }
          UserUtils::userForgotPassword($_POST['username'], $_POST['email']);
          UI::addMessage(UI::SUCCESS, "Password reset! You should receive an email soon.");
          break;
        default:
          UI::addMessage(UI::ERROR, "Invalid action!");
          break;
      }
    }
    catch (Throwable $e) {
      UI::addMessage(UI::ERROR, $e->getMessage());
    }
  }
}