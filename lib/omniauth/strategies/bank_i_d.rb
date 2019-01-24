require 'multi_json'
require 'jwt'
require 'omniauth/strategies/oauth2'
require 'addressable/uri'

module OmniAuth
  module Strategies
    class BankID < OmniAuth::Strategies::OAuth2

      option :skip_jwt, false
      option :authorize_options, [:access_type, :hd, :login_hint, :prompt, :request_visible_actions, :scope, :state, :redirect_uri, :include_granted_scopes, :openid_realm]
      option :scope, "openid profile address phone email nnin nnin_altsub aml_person/basic aml_person/noauthentication aml_organization/basic" 
      option :response_type, 'code id_token'

      def client
        @client ||= ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end
          params[:scope] = options[:scope]
          session['omniauth.state'] = params[:state] if params['state']
        end
      end

      uid { t_info.dig('sub') || verified_email }

      info do
        out = prune!({
          name: t_info.dig('name'),
          email: t_info.dig('email'),
          first_name: t_info.dig('given_name'),
          last_name: t_info.dig('family_name'),
          phone: t_info.dig('phone_number'),
          address: t_info.dig('address', 'formatted') || aml_info('address').dig('address'),
          ssn: t_info.dig('nnin'),
          postcode: t_info.dig('address', 'postal_code'),
          region: t_info.dig('address', 'locality'),
          pep_info: aml_info('pep') { 'nationality=NO&includeReport=true' }
          #report_link: aml_info('report', @aml_info[:reportId])
        })
      end

      # quickly get info from BANKID API without doing user authentication
      def quick_info(first_name:, last_name:, ssn:, nationality: 'NO')
        opts = {
          firstName: first_name,
          lastName: last_name,
          ssn: ssn,
          nationality: nationality,
          includeReport: true
        }
        out = prune!({
          pep_info: aml_info('noauth_pep') { opts.to_param },
          address: aml_info('noauth_address') { opts.to_param }
        })
      end

      extra do
        hash = {}
        hash[:id_token] = access_token['id_token']
        if !options[:skip_jwt] && !access_token['id_token'].nil?
          hash[:id_info] = JWT.decode(
            access_token['id_token'], nil, false, {
              verify_iss: true,
              iss: options[:client_options][:site],
              verify_aud: true,
              aud: options.client_id,
              verify_sub: false,
              verify_expiration: true,
              verify_not_before: true,
              verify_iat: true,
              verify_jti: false
            }).first
        end
        prune! hash
      end

      def aml_info(kind)
        url = options[:client_options]["aml_#{kind}_url".to_sym]
        opts = bearer_request_options
        if block_given?
          extra_params = yield
          url += "?#{extra_params}"
        else
          url += "?nationality=NO"
        end
        @aml_info = parse_response(client_request(:get, url, opts))
      end

      def t_info
        url = options[:client_options][:userinfo_url]
        @t_info ||= parse_response(client_request(:get, url, bearer_request_options))
      end

      def build_access_token_bankid(flow = 'authorization_code')
        opts = {
          raise_errors: false,
          parse: nil, 
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': "Basic #{Base64.strict_encode64(options.client_id + ':' + options.client_secret)}"
          }
        }
        opts[:body] =
          if flow == 'client_credentials'
            {
              grant_type: 'client_credentials',
              scope: options[:scope]
            }
          else
            {
              grant_type: 'authorization_code', 
              code: request.params['code'], 
              redirect_uri: options[:client_options][:redirect_uri],
              state: request.params['state']
            }
          end
        url = options[:client_options][:token_url]
        response = client.request(:post, url, opts)
        if opts[:raise_errors] && !(response.parsed.is_a?(Hash) && response.parsed['access_token'])
          error = Error.new(response)
          raise(error)
        end
        h = response.parsed.dup
        h[:header_format]  = 'Bearer %s'
        ::OAuth2::AccessToken.new(client, h.delete('access_token') || h.delete(:access_token), h)
      end

      def custom_build_access_token
        if request.params['code'] && request.params['redirect_uri']
          verifier = request.params['code']
          redirect_uri = request.params['redirect_uri']
          client.auth_code.get_token(verifier, get_token_options(redirect_uri), deep_symbolize(options.auth_token_params || {}))
        elsif verify_token(request.params['id_token'], request.params['access_token'])
          ::OAuth2::AccessToken.from_hash(client, request.params.dup)
        else
          build_access_token_bankid
        end
      end
      alias_method :build_access_token, :custom_build_access_token


      private

      # TODO: add support to handle PEP report file download
      def parse_response(response)
        return {} unless response
        if response.headers["content-type"]&.include? 'application/jwt'
          JWT.decode(response.body, nil, false)[0]
        elsif response.headers['content-type']&.include? 'application/pdf'
          response.body
        else
          response.parsed
        end
      end

      def client_request(method, url, options = {})
        begin
           resp = client.request(:get, url, options)
           case resp.status
           when 400..599
             Rails.logger.error "BankID OIDC client error: #{resp&.response&.reason_phrase}, request url: #{url}"
           end
           resp
        rescue StandardError => e
          Rails.logger.error "BankID OIDC client error: #{e.message}, response status: #{resp.status}"
          raise Error.new(resp)
          nil
        end
      end

      def bearer_request_options
        {
          raise_errors: false,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': "Bearer #{access_token.token}"
          },
          body: {}
        }
      end
      
      def get_token_options(redirect_uri)
        { redirect_uri: redirect_uri }.merge(token_params.to_hash(symbolize_keys: true))
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def verified_email
        t_info['email_verified'] ? t_info['email'] : nil
      end

      def verify_token(id_token, access_token)
        return false unless (id_token && access_token)
        raw_response = client.request(:get, options[:client_options][:site] + options[:client_options][:introspection_url], params: {
          id_token: id_token,
          access_token: access_token
        }).parsed
        raw_response['issued_to'] == options.client_id
      end
    end
  end
end

OmniAuth.config.add_camelization 'bankid', 'BankID'
OmniAuth.config.add_camelization 'bank_id', 'BankID'
