require 'httparty'
require 'hashie'
require 'ambisafe'

module Tether
  class Client
    include HTTParty

    BASE_URI = 'https://wallet.tether.to/api/v1'

    def initialize(api_key='', api_secret='', password='', options={})
      @api_key = api_key
      @api_secret = api_secret
      @account_password = password

      @base_uri = options.has_key?(:base_uri) ? options[:base_uri] : BASE_URI

      # forward to HTTParty
      options[:format] ||= :json
      options.each do |k,v|
        self.class.send k, v
      end
    end

    def get_account
      get '/account'
    end

    def balances
      get '/balances'
    end

    def exchange_rates
      get '/exchange_rates'
    end

    # transactions
    def transactions
      get '/transactions'
    end

    def get_transaction(id)
      get "/transactions/#{id}"
    end

    def new_transaction(params)
      result = post '/transactions/prepare', params

      signed_transaction = sign_transaction(result.transaction)

      post '/transactions', {
          :transaction => signed_transaction,
          :signed_tx_info => result.signed_tx_info
      }
    end

    # exchange orders
    def exchange_orders
      get '/exchange_orders'
    end

    def get_exchange_order(id)
      get "/exchange_orders/#{id}"
    end

    def new_exchange_order(params)
      post '/exchange_orders', params
    end

    # invoices
    def new_invoice(params)
      post '/invoices', params
    end

    def check_signature(type, params)
      raise ApiError, 'Request is unsigned!' unless params.has_key? 'signature'
      string_to_sign = ''

      case type
        when :invoice_callback
          %w(id deposit_address invoiced_amount received_amount currency status).each { |field|
            raise ApiError, "Missing field: #{field}" unless params.has_key? field
            string_to_sign += params[field].to_s
          }
          string_to_sign += @api_secret
        else
          raise ApiError, "Cannot check signature of type #{type}"
      end

      raise ApiError, 'Signature is corrupted/fake!' unless params['signature'] == Digest::MD5.hexdigest(string_to_sign)
    end

    # Wrappers for the main HTTP verbs

    def get(path, options={})
      do_request :get, path, options
    end

    def post(path, options={})
      do_request :post, path, options
    end

    def put(path, options={})
      do_request :put, path, options
    end

    def delete(path, options={})
      do_request :delete, path, options
    end

    def do_request(verb, uri, options={})
      path = @base_uri + uri

      if [:get, :delete].include? verb
        request_options = {}
        path = "#{@base_uri}#{uri}?#{URI.encode_www_form(options)}" unless options.empty?
        content_md5 = md5_base64digest('')
      else
        body = options.to_json
        request_options = { body: body }
        content_md5 = md5_base64digest(body)
      end

      # Generate valid headers and signature
      headers = {
          'Content-MD5' => content_md5,
          'Date' => Time.now.utc.httpdate,
          'Content-Type' => 'application/json',
      }
      canonical_string = [ headers['Content-Type'],
                           headers['Content-MD5'],
                           URI(@base_uri + uri).path,
                           headers['Date']
      ].join(',')

      signature = hmac_signature(canonical_string)
      headers['Authorization'] = "APIAuth #{@api_key}:#{signature}"
      request_options[:headers] = headers

      # forward to HTTParty
      response = self.class.send(verb, path, request_options)
      puts response.body if @base_uri != BASE_URI
      parsed_response = JSON.parse(response.body)
      hash = parsed_response.kind_of?(Array) ? parsed_response.collect { |item| Hashie::Mash.new(item) } : Hashie::Mash.new(parsed_response)
      raise ApiError.new(hash.error) if hash.kind_of?(Hashie::Mash) && hash.error
      hash
    end

    class ApiError < StandardError; end

    private

    def hmac_signature(canonical_string)
      digest = OpenSSL::Digest.new('sha1')
      b64_encode(OpenSSL::HMAC.digest(digest, @api_secret, canonical_string))
    end

    def b64_encode(string)
      if Base64.respond_to?(:strict_encode64)
        Base64.strict_encode64(string)
      else
        # Fall back to stripping out newlines on Ruby 1.8.
        Base64.encode64(string).gsub(/\n/, '')
      end
    end

    def md5_base64digest(string)
      if Digest::MD5.respond_to?(:base64digest)
        Digest::MD5.base64digest(string)
      else
        b64_encode(Digest::MD5.digest(string))
      end
    end

    def sign_transaction(transaction)
      account = get_account
      private_key = Ambisafe.decrypt_priv_key_from_container(account.data, get_account_password)
      transaction["user_signatures"] = Ambisafe.sign(transaction["sighashes"], private_key)
      transaction
    end

    def get_account_password
      @account_password
    end

  end
end
