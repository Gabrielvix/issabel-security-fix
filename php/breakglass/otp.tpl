<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{$PAGE_NAME}</title>
  <style>
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      min-height: 100%;
      font-family: "Noto Sans", "Segoe UI", Tahoma, sans-serif;
      background: {$LOGIN_COLOR_2};
      color: #eee;
    }
    .wrap {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: rgba(0, 0, 0, 0.72);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 16px;
      padding: 32px 28px 24px;
      box-shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
    }
    .logo {
      display: block;
      margin: 0 auto 18px;
      max-width: 200px;
      height: auto;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 1.25rem;
      font-weight: 600;
      text-align: center;
      color: #fff;
    }
    .hint {
      margin: 0 0 18px;
      color: #c8c8c8;
      font-size: 0.92rem;
      text-align: center;
      line-height: 1.4;
    }
    .error {
      margin: 0 0 14px;
      padding: 10px 12px;
      border-radius: 8px;
      background: rgba(220, 53, 69, 0.2);
      border: 1px solid rgba(220, 53, 69, 0.45);
      color: #ffb4b4;
      font-size: 0.92rem;
    }
    label {
      display: block;
      margin-bottom: 6px;
      font-size: 0.85rem;
      color: #ddd;
    }
    input[type="text"] {
      width: 100%;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      background: {$LOGIN_COLOR_1};
      color: #fff;
      font-size: 1.25rem;
      letter-spacing: 0.25em;
      text-align: center;
      outline: none;
    }
    input[type="text"]:focus {
      border-color: #4ea1ff;
      box-shadow: 0 0 0 3px rgba(78, 161, 255, 0.25);
    }
    button {
      width: 100%;
      margin-top: 16px;
      padding: 12px 16px;
      border: 0;
      border-radius: 10px;
      background: #1a73e8;
      color: #fff;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: #1558b0; }
    .foot {
      margin-top: 18px;
      text-align: center;
      font-size: 0.78rem;
      color: #999;
    }
    .back {
      display: block;
      margin-top: 12px;
      text-align: center;
      color: #9ec7ff;
      font-size: 0.9rem;
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      {if $LOGO_SRC ne ''}
        <img class="logo" src="{$LOGO_SRC}" alt="Issabel" width="200" height="62">
      {/if}
      <h1>{$PAGE_NAME}</h1>
      <p class="hint">{$WELCOME}</p>
      {if $OTP_ERROR ne ''}
        <p class="error">{$OTP_ERROR}</p>
      {/if}
      <form method="post" autocomplete="off" action="index.php">
        <label for="isf_otp_code">{$CODE}</label>
        <input id="isf_otp_code" type="text" name="isf_otp_code" placeholder="000000"
               inputmode="numeric" pattern="[0-9]*" maxlength="8"
               autocomplete="one-time-code" autofocus required>
        <button type="submit" name="isf_otp_submit" value="1">{$SUBMIT}</button>
      </form>
      <a class="back" href="index.php">Voltar ao login</a>
      <div class="foot">Issabel {$ISSABEL_LICENSED} GPL. {$currentyear}.</div>
    </div>
  </div>
</body>
</html>
