require 'httparty'
require 'hashie'
require 'bitcoin'

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
      get '/account.json'
    end

    def balances
      get '/balances.json'
    end

    def exchange_rates
      get '/exchange_rates.json'
    end

    # transactions
    def transactions
      get '/transactions.json'
    end

    def get_transaction(id)
      get "/transactions/#{id}.json"
    end

    def new_transaction(params)
      result = post '/transactions/prepare.json', params

      signed_transaction = sign_transaction(result.transaction)

      post '/transactions.json', {
          :transaction => signed_transaction,
          :signed_tx_info => result.signed_tx_info
      }
    end

    # exchange orders
    def exchange_orders
      get '/exchange_orders.json'
    end

    def get_exchange_order(id)
      get "/exchange_orders/#{id}.json"
    end

    def new_exchange_order(params)
      result = post '/exchange_orders/prepare.json', params

      signed_transaction = sign_transaction(result.transaction)

      post '/exchange_orders.json', {
          :transaction => signed_transaction,
          :signed_tx_info => result.signed_tx_info
      }
    end

    # invoices
    def new_invoice(params)
      post '/invoices.json', params
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
      private_key = decrypt_priv_key_from_container(account.data, account_password)
      transaction["user_signatures"] = sign(transaction["sighashes"], private_key)
      transaction
    end

    def sign(sighashes, priv_key)
      sighashes.map { |sighash| sign_hash(sighash, priv_key) }
    end

    def sign_hash(sighash, priv_key)
      keypair = Bitcoin.open_key priv_key
      sig = Bitcoin.sign_data(keypair, [sighash].pack("H*"))
      sig.unpack("H*").first
    end

    def decrypt_priv_key_from_container(container, password)
      data = container["data"].scan(/../).map(&:hex).pack('c*')
      iv = container["iv"].scan(/../).map(&:hex).pack('c*')
      priv_key = decrypt(data, container["salt"], iv, password)
      priv_key.unpack('H*')[0]
    end

    def decrypt(encrypted, salt, iv, password)
      begin
        decipher = OpenSSL::Cipher::AES.new(256, :CBC)
        decipher.decrypt
        decipher.key = derive_key(salt, password)
        decipher.iv = iv
        decrypted = decipher.update(encrypted) + decipher.final
        decrypted
      rescue OpenSSL::Cipher::CipherError => e
        e.message
      end
    end

    def derive_key(salt, password)
      OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 1000, 32, OpenSSL::Digest::SHA512.new)
    end

    def account_password
      @account_password
    end

  end
end
