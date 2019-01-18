## OmniAuth OpenID Connect Strategy for BankID Norge REST API

 based  on omniauth-oauth2 base strategy 


 Example configuration to be used with Devise Omniauth (put this in config/initializers/devise.rb:<br/>
 assumming that oidc_config_file specified in secrets.yml

```ruby
  bankid_opts = Rails.application.secrets[:bankid]
  load  Rails.root.join('config', bankid_opts[:oidc_config_file])

  config.omniauth :bank_id, bankid_opts[:client_id], bankid_opts[:client_secret], {
      name: :bank_id,
      client_options: {
        site: OIDC_config[:issuer],
        authorize_url: OIDC_config[:authorization_endpoint],
        token_url: OIDC_config[:token_endpoint],
        redirect_uri: bankid_opts[:callback_url], 
        userinfo_url: OIDC_config[:userinfo_endpoint],
        aml_address_url: "#{OIDC_config[:aml_baseurl]}/person/address/current",
        aml_pep_url: "#{OIDC_config[:aml_baseurl]}/person/sanction_pep",
        aml_report_url:  "#{OIDC_config[:aml_baseurl]}/person/report",
        aml_noauth_pep_url: "#{OIDC_config[:aml_baseurl]}/person/noauthentication/sanction_pep",
        aml_noauth_address_url: "#{OIDC_config[:aml_baseurl]}/person/noauthentication/address"
      }
   }
```

 Example content of OIDC configuration file retrieved with GET request to<br/>
 https://oidc-current.bankidapis.no/auth/realms/current/.well-known/openid-configuration</br>
 (see https://confluence.bankidnorge.no/confluence/pdoidcl/technical-documentation/rest-api/openid-configuration)<br/>
```ruby
OIDC_config = {
  "issuer": "https://oidc-current.bankidapis.no/auth/realms/current",
  "authorization_endpoint": "https://oidc-current.bankidapis.no/auth/realms/current/precheck/auth",
  "token_endpoint": "https://oidc-current.bankidapis.no/auth/realms/current/protocol/openid-connect/token",
  "token_introspection_endpoint": "https://oidc-current.bankidapis.no/auth/realms/current/protocol/openid-connect/token/introspect",
  "userinfo_endpoint": "https://tinfo-current.bankidapis.no/userinfo",
  "end_session_endpoint": "https://oidc-current.bankidapis.no/auth/realms/current/protocol/openid-connect/logout",
  "jwks_uri": "https://oidc-current.bankidapis.no/auth/realms/current/protocol/openid-connect/certs",
  "check_session_iframe": "https://oidc-current.bankidapis.no/auth/realms/current/protocol/openid-connect/login-status-iframe.html",
  "grant_types_supported": ["authorization_code","implicit","refresh_token","password","client_credentials"],
  "response_types_supported": ["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],
  "subject_types_supported": ["public","pairwise"],
  "aml_baseurl": "https://aml-current.bankidapis.no"
}
```
