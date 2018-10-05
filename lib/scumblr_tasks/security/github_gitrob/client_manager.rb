module Gitrob
    module Github
        class ClientManager
            USER_AGENT = 'Gitrob v1.1.2'.freeze

            attr_reader :clients

            class NoClientsError < StandardError; end

            def initialize(config)
                @config  = config
                @clients = []
                config[:access_tokens].each do |token|
                    clients << create_client(token)
                end
            end

            def sample
                raise NoClientsError if clients.count.zero?
                clients.sample
            end

            def remove(client)
                clients.delete(client)
            end

            private

            def create_client(access_token)
                ::Github.new(
                    oauth_token: access_token,
                    endpoint: @config[:endpoint],
                    ssl: @config[:ssl],
                    user_agent: USER_AGENT,
                    auto_pagination: true,
                    per_page: 100)
            end
        end
    end
end
