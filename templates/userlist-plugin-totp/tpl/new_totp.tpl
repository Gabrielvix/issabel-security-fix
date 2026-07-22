<fieldset>
  <legend><b>{$LBL_TOTP_TITLE}</b></legend>
  <table width="100%" border="0" cellspacing="0" cellpadding="4" class="tabForm">
    <tr>
      <td colspan="2" class="letra12">{$LBL_TOTP_HELP}</td>
    </tr>
    <tr>
      <td colspan="2" class="letra12"><em>{$LBL_TOTP_BG}</em></td>
    </tr>
    <tr>
      <td width="20%">{$LBL_TOTP_STATUS}:</td>
      <td width="80%"><strong>{$TOTP_STATUS_TXT}</strong></td>
    </tr>
{if $TOTP_CONFIGURED}
    <tr>
      <td>{$LBL_TOTP_SECRET}:</td>
      <td><code>{$TOTP_SECRET}</code></td>
    </tr>
    {if $TOTP_QR ne ''}
    <tr>
      <td>QR:</td>
      <td><img src="{$TOTP_QR}" alt="TOTP QR" width="180" height="180"></td>
    </tr>
    {/if}
    <tr>
      <td>{$LBL_TOTP_URI}:</td>
      <td style="word-break:break-all;font-size:11px;"><code>{$TOTP_URI}</code></td>
    </tr>
{/if}
    <tr>
      <td>{$LBL_TOTP_TITLE}:</td>
      <td>
        <label><input type="radio" name="isf_totp_action" value="keep" checked> {$LBL_TOTP_KEEP}</label><br>
        <label><input type="radio" name="isf_totp_action" value="generate"> {$LBL_TOTP_GEN}</label><br>
        <label><input type="radio" name="isf_totp_action" value="clear"> {$LBL_TOTP_CLEAR}</label>
      </td>
    </tr>
  </table>
</fieldset>
