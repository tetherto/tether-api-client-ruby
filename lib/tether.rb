require 'httparty'
require 'hashie'

module Tether
  class Client
    include HTTParty

    BASE_URI = 'https://wallet.tether.to/api/v1'

    def initialize(api_key='', api_secret='', options={})
      @api_key = api_key
      @api_secret = api_secret

      # defaults
      options[:base_uri] ||= BASE_URI
      @base_uri = options[:base_uri]
      options[:format] ||= :json

      # forward to HTTParty
      options.each do |k,v|
        self.class.send k, v
      end
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
      post '/transactions', params
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
      path = uri

      if [:get, :delete].include? verb
        request_options = {}
        path = "#{uri}?#{URI.encode_www_form(options)}" unless options.empty?
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

  end
end
