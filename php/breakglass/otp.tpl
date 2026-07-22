<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{$PAGE_NAME}</title>
  <link rel="stylesheet" href="{$WEBPATH}themes/{$THEMENAME}/css/bootstrap.css">
  <link rel="stylesheet" href="{$WEBPATH}themes/{$THEMENAME}/css/neon-core.css">
  <link rel="stylesheet" href="{$WEBPATH}themes/{$THEMENAME}/css/neon-theme.css">
  <link rel="stylesheet" href="{$WEBPATH}themes/{$THEMENAME}/css/neon-forms.css">
  <link rel="stylesheet" href="{$WEBPATH}themes/{$THEMENAME}/css/purple-login.css">
  <style>
    .login-header { background-color: {$LOGIN_COLOR_1} !important; }
    body { background-color: {$LOGIN_COLOR_2} !important; }
    .isf-error { color: #ffb4b4; margin-bottom: 1rem; }
    .isf-hint { color: #ccc; font-size: 0.9em; margin-bottom: 1.2rem; }
  </style>
</head>
<body class="page-body login-page login-form-fall">
<div class="login-container">
  <div class="login-header login-caret">
    <div class="login-content">
      <img src="{$WEBPATH}themes/{$THEMENAME}/images/issabel_logo_mini.png" width="200" height="62" alt="Issabel">
    </div>
  </div>
  <div class="login-form">
    <div class="login-content">
      <form method="post" autocomplete="off">
        <h3 style="color:#eee;">{$PAGE_NAME}</h3>
        <p class="isf-hint">{$WELCOME}</p>
        {if $OTP_ERROR ne ''}
          <p class="isf-error">{$OTP_ERROR}</p>
        {/if}
        <div class="form-group">
          <div class="input-group">
            <div class="input-group-addon"><i class="entypo-key"></i></div>
            <input type="text" class="form-control" name="isf_otp_code" placeholder="{$CODE}"
                   inputmode="numeric" pattern="[0-9]*" maxlength="8" autocomplete="one-time-code" autofocus>
          </div>
        </div>
        <div class="form-group">
          <button type="submit" class="btn btn-primary btn-block btn-login" name="isf_otp_submit">
            {$SUBMIT}
          </button>
        </div>
      </form>
      <div class="login-bottom-links">
        Issabel {$ISSABEL_LICENSED} GPL. {$currentyear}.
      </div>
    </div>
  </div>
</div>
</body>
</html>
