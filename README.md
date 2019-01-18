# OmniAuth OpenID Connect Strategy for BankID Norge REST API

 based  on omniauth-oauth2 base strategy 


 Example configuration to be used with Devise Omniauth (put this in config/initializers/devise.rb:
 assumming that oidc_config_file specified in secrets.yml

```
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
