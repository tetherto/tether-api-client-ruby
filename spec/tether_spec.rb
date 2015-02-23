require 'fakeweb'
require 'tether'

describe Tether::Client do
  BASE_URI = 'http://tether.to/api/fake' # switching to http (instead of https) seems to help FakeWeb

  before :all do
    @client = Tether::Client.new('key', 'secret', { base_uri: BASE_URI })
    FakeWeb.allow_net_connect = false
  end

  it 'should handle errors' do
    hoax :get, '/balances', { error: 'Fake error' }
    expect { @client.balance }.to raise_error(Tether::Client::ApiError, 'Fake error')
  end

  it 'should get balance' do
    hoax :get, '/balances', [{ currency: 'BTC', confirmed: "22.00000000", pending: "0.0" }, { currency: 'USDT', confirmed: "100.00000000", pending: "0.0" }]
    expect(@client.balances[0].confirmed).to eq("22.00000000")
    expect(@client.balances[1].currency).to eq("USDT")
  end

  it 'should get exchange_rates' do
    hoax :get, '/exchange_rates', [{source_currency: "BTC", target_currency: "USDT", exchange_rate: "246.5"}, {source_currency: "USDT", target_currency: "BTC", exchange_rate: "0.0040568"}]
    expect(@client.exchange_rates[0].exchange_rate).to eq("246.5")
  end

  private

  def hoax(method, path, response)
    FakeWeb.register_uri(method, "#{BASE_URI}#{path}", body: response.to_json)
  end

end