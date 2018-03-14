#     Copyright 2016 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

require 'uri'
require 'net/http'
require 'json'
require 'rest-client'
require 'time'
require 'byebug'
class ScumblrTask::GithubGitrobAnalyzer < ScumblrTask::Base
    def self.task_type_name
        "Github Gitrob Code Search"
    end

    def self.task_category
        "Security"
    end

    def self.description
        "Search github repos for specific values and create vulnerabilities for matches using gitrob's search functionality."
    end

    def self.config_options
        {
            :github_api_endpoint => { name: "Github Endpoint",
                description: "Allow configurable endpoint for Github Enterprise deployments",
                required: false
            }
        }
    end

    def self.options
        return super.merge({
            :github_oauth_token =>{ name: "Github OAuth Token",
                description: "Setting this token provides the access needed to search Github organizations or repos",
                required: true
            },
            :severity => {name: "Finding Severity",
                description: "Set severity to either observation, high, medium, or low",
                required: true,
                type: :choice,
                default: :observation,
            choices: [:observation, :high, :medium, :low]},
            :key_suffix => {name: "Key Suffix",
                description: "Provide a key suffix for testing out experimental regular expressions",
                required: false,
            type: :string},
            :tags => {name: "Tag Results",
                description: "Provide a tag for newly created results",
                required: false,
                type: :tag
            },
            :max_results => {name: "Limit search results",
                description: "Limit search results.",
                required: true,
                default: "200",
            type: :string},
            :user => {name: "Scope To User Or Organization",
                description: "Limit search to an Organization or User.",
                required: true,
            type: :string},

        })
    end

    def rate_limit_sleep(remaining, reset, no_limit)
        # This method sleeps until the rate limit resets
        if remaining.to_i <= 1 && no_limit == false
            time_to_sleep = (reset.to_i - Time.now.to_i)
            puts "Sleeping for #{time_to_sleep}"
            sleep (time_to_sleep + 1) if time_to_sleep > 0
        end
    end


    def initialize(options={})
        super

        @github_oauth_token = @github_oauth_token.to_s.strip
        @github_api_endpoint = @github_api_endpoint.to_s.strip.empty? ? "https://api.github.com" : @github_api_endpoint

        @search_scope = {}
        @results = []
        @terms = []
        @total_matches = 0

        # End of remove
        if(@options[:key_suffix].present?)
            @key_suffix = "_" + @options[:key_suffix].to_s.strip
            puts "A key suffix was provided: #{@key_suffix}."
        end

        # Set the max results if specified, otherwise default to 200 results
        @options[:max_results] = @options[:max_results].to_i > 0 ? @options[:max_results].to_i : 200

        # Check that they actually specified a repo or org.
        unless @options[:user].present?
            raise ScumblrTask::TaskException.new("No user, or org provided.")
            return
        end

        if @options[:user].present?
            @search_scope.merge!(@options[:user] => "user")
        end
    end

    def run
        require "thread/pool"
        Thread::Pool.abort_on_exception = true

        # Hack: added gitrob functionality
        client_manager = Gitrob::Github::ClientManager.new({
            :access_tokens => [@github_oauth_token],
            :endpoint => @github_api_endpoint,
            # TODO: This is not robust. Do we really need the site? If thats the case, add it as task parameter.
            :site => @github_api_endpoint[0..@github_api_endpoint.index(/api/)-2],
            :ssl => {:verify => true},})
        # TODO: gitrob does not support repositories as input, only users and organizations. Implement if required.
        logins = @search_scope.keys
        data_manager = Gitrob::Github::DataManager.new(logins, client_manager)
        thread_pool do |pool|
            data_manager.gather_owners(pool)
        end
        thread_pool do |pool|
            data_manager.gather_repositories(pool)
        end

        data_manager.owners.each do |owner|
            thread_pool do |pool|
                data_manager.repositories_for_owner(owner).each do |repo|
                    pool.process do
                        results = analyze_blobs(data_manager.blobs_for_repository(repo), repo, owner, data_manager)
                        report_results(results, repo)
                    end
                end
            end
        end
    end

    def analyze_blobs(blobs, repo, owner, data_manager)
        results = []
        blobs.each do |blob|
            blob_string = data_manager.blob_string_for_blob_repo(blob)

            allowed_columns = Gitrob::Models::Blob.allowed_columns
            data = blob.select { |k, _v| allowed_columns.include?(k.to_sym) }
            db_blob = Gitrob::Models::Blob.new(data)
            db_blob.repository = repo
            db_blob.owner = owner

            result = Gitrob::BlobObserver.observe(db_blob, blob_string)
            results += result if !result.empty?
        end
        return results
    end

    def report_results(results, repo)
        vulnerabilities = []

        results.each do |result|
            vuln = create_vulnerability(result)
            vulnerabilities << vuln if vuln
        end
        upsert_vulnarabilities(vulnerabilities, repo)
    end

    def create_vulnerability(result)
        vuln = Vulnerability.new

        if(@options[:key_suffix].present?)
            vuln.key_suffix = @options[:key_suffix]
        end
        vuln.source = "github"
        vuln.task_id = @options[:_self].id.to_s
        vuln.severity = @options[:severity]
        vuln.type = '"' + result[:caption] + '"' + " - #{result[:part]} match"

        begin
            vuln.term = result[:caption]
            vuln.file_name = result[:file_name]
            vuln.url = result[:url]
            vuln.code_fragment = result[:code_fragment]
            vuln.match_location = result[:part]

            return vuln
        rescue => e
            create_event("Unable to add metadata.\n\n. Exception: #{e.message}\n#{e.backtrace}", "Warn")
        end
    end

    def upsert_vulnarabilities(vulnerabilities, repo)
        metadata = metadata(repo)
        res = Result.where(url: repo[:html_url].downcase).first
        if res.present?
            res.update_vulnerabilities(vulnerabilities)
            res.metadata.merge!({"repository_data" => metadata["repository_data"]})
            if @options[:tags].present?
                res.add_tags(@options[:tags])
            end
            res.save!
            # Do not create new result simply append vulns to results
        else
            github_result = Result.new(url: repo[:html_url].downcase, title: repo[:full_name].to_s + " (Github)", domain: "github", metadata: {"repository_data" => metadata["repository_data"],})
            if @options[:tags].present?
                github_result.add_tags(@options[:tags])
            end
            github_result.save!
            github_result.update_vulnerabilities(vulnerabilities)
        end
    end

    def metadata(repo)
        search_metadata ||= {}
        search_metadata["repository_data"] ||= {}
        search_metadata["repository_data"]["name"] = repo[:full_name]
        search_metadata["repository_data"]["slug"] = repo[:full_name]
        search_metadata["repository_data"]["project"] = repo.owner[:login]
        search_metadata["repository_data"]["project_name"] = repo.owner[:login]
        search_metadata["repository_data"]["project_type"] = repo.owner[:type] == "User" ? "User" : "Project"
        search_metadata["repository_data"]["private"] = repo[:private]
        search_metadata["repository_data"]["source"] = "github"
        search_metadata["repository_data"]["link"] = repo[:html_url]
        search_metadata["repository_data"]["repository_host"] = @github_api_endpoint.gsub(/\Ahttps?:\/\//,"").gsub(/\/.+/,"")
        return search_metadata
    end

    def thread_pool
      pool = Thread::Pool.new(5)
      yield pool
      pool.shutdown
    end
end

module Gitrob
    module Github
        class ClientManager
            USER_AGENT = "Gitrob v1.1.2"

            attr_reader :clients

            class NoClientsError < StandardError; end

            def initialize(config)
                @config  = config
                @mutex   = Mutex.new
                @clients = []
                config[:access_tokens].each do |token|
                    clients << create_client(token)
                end
            end

            def sample
                @mutex.synchronize do
                    fail NoClientsError if clients.count.zero?
                    clients.sample
                end
            end

            def remove(client)
                @mutex.synchronize do
                    clients.delete(client)
                end
            end

            private

            def create_client(access_token)
                ::Github.new(
                    :oauth_token     => access_token,
                    :endpoint        => @config[:endpoint],
                    :site            => @config[:site],
                    :ssl             => @config[:ssl],
                    :user_agent      => USER_AGENT,
                    :auto_pagination => true
                )
            end
        end
    end
end


module Gitrob
    module Github
        class DataManager
            attr_reader :client_manager,
            :unknown_logins,
            :owners,
            :repositories

            def initialize(logins, client_manager)
                @logins = logins
                @client_manager = client_manager
                @unknown_logins = []
                @owners = []
                @repositories = []
                @repositories_for_owners = {}
                @mutex = Mutex.new
            end

            def gather_owners(thread_pool)
                @logins.each do |login|
                    next unless owner = get_owner(login)
                    @owners << owner
                    @repositories_for_owners[owner["login"]] = []
                    next unless owner["type"] == "Organization"
                    get_members(owner, thread_pool) if owner["type"] == "Organization"
                end
                @owners = @owners.uniq {|o| o["login"]}
            end

            def gather_repositories(thread_pool)
                owners.each do |owner|
                    thread_pool.process do
                        repositories = get_repositories(owner)
                        with_mutex do
                            save_repositories(owner, repositories)
                        end
                        yield owner, repositories if block_given?
                    end
                end
            end

            def repositories_for_owner(owner)
                @repositories_for_owners[owner["login"]]
            end


            def blob_string_for_blob_repo(blob)
                download_blob(blob)
            rescue ::Github::Error::Forbidden => e
                # Hidden GitHub feature?
                raise e unless e.message.include?("403 Repository access blocked")
                []
            rescue ::Github::Error::NotFound => e
                []
            rescue ::Github::Error::ServiceError => e
                raise e unless e.message.include?("409 Git Repository is empty")
                []
            end

            def blobs_for_repository(repository)
                get_blobs(repository)
            rescue ::Github::Error::Forbidden => e
                # Hidden GitHub feature?
                raise e unless e.message.include?("403 Repository access blocked")
                []
            rescue ::Github::Error::NotFound
                []
            rescue ::Github::Error::ServiceError => e
                raise e unless e.message.include?("409 Git Repository is empty")
                []
            end

            private

            def get_owner(login)
                github_client do |client|
                    client.users.get(:user => login)
                end
            rescue ::Github::Error::NotFound
                @unknown_logins << login
                nil
            end

            def get_members(org, thread_pool)
                github_client do |client|
                    client.orgs.members.list(:org_name => org["login"]) do |owner|
                        thread_pool.process do
                            owner = get_owner(owner["login"])
                            with_mutex do
                                @owners << owner
                                @repositories_for_owners[owner["login"]] = []
                            end
                        end
                    end
                end
            end

            def get_repositories(owner)
                if owner["type"] == "Organization"
                    github_client do |client|
                        client.repos.list(:org => owner["login"], :type => "sources")
                    end
                else
                    github_client do |client|
                        client.repos.list(
                        :user => owner["login"]).reject {|r| r["fork"]}
                    end
                end
            end

            def download_blob(blob)
                github_client do |client|
                    b64blob = client.get_request(blob.url)["content"]
                    Base64.decode64(b64blob)
                end
            end

            def get_blobs(repository)
                github_client do |client|
                    client.get_request(
                        "/repos/#{repository[:full_name]}/git/trees/" \
            "#{repository[:default_branch]}",
                    ::Github::ParamsHash.new(:recursive => 1))["tree"].reject {|b| b["type"] != "blob"}
                end
            end

            def github_client
                client = @client_manager.sample
                yield client
            rescue ::Github::Error::Forbidden => e
                raise e unless e.message.include?("API rate limit exceeded")
                @client_manager.remove(client)
            rescue ::Github::Error::Unauthorized
                @client_manager.remove(client)
            end

            def save_repositories(owner, repositories)
                @repositories += repositories
                @repositories_for_owners[owner["login"]] = repositories
            end

            def with_mutex
                @mutex.synchronize {yield}
            end
        end
    end
end

module Gitrob
    module Models
        class Blob

            SHA_REGEX = /[a-f0-9]{40}/
            TEST_BLOB_INDICATORS = %w(test spec fixture mock stub fake demo sample)
            LARGE_BLOB_THRESHOLD = 102_400

            attr_accessor :repository, :owner
            attr_reader :path

            def initialize(data)
                @path = data["path"]
                @size = data["size"]
                @sha = data["sha"]
                @content = data["content"]
            end

            def self.allowed_columns
                [:path, :size, :sha, :content]
            end

            def validate
                super
                validates_presence [:path, :size, :sha]
                validates_format SHA_REGEX, :sha
            end

            def filename
                File.basename(path)
            end

            def extension
                File.extname(path)[1..-1]
            end

            def test_blob?
                TEST_BLOB_INDICATORS.each do |indicator|
                    return true if path.downcase.include?(indicator)
                end
                false
            end

            def html_url
                "#{repository.html_url}/blob/#{repository.default_branch}/#{path}"
            end

            def history_html_url
                "#{repository.html_url}/commits/#{repository.default_branch}/#{path}"
            end

            def large?
                size.to_i > LARGE_BLOB_THRESHOLD
            end
        end
    end
end


module Gitrob
    class BlobObserver
        SIGNATURES_FILE_PATH = File.expand_path(
        "/etc/gitrob_signatures/signatures.json", __FILE__)
        CUSTOM_SIGNATURES_FILE_PATH = File.join(
        Dir.home, ".gitrobsignatures")

        REQUIRED_SIGNATURE_KEYS = %w(part type pattern caption description)
        ALLOWED_TYPES = %w(regex match)
        ALLOWED_PARTS = %w(path filename extension content)

        class Signature < OpenStruct;
        end
        class CorruptSignaturesError < StandardError;
        end

        def self.observe(blob, blob_string)
            blob_findings = []
            signatures.each do |signature|
                if signature.part == "content"
                    if blob_string != nil
                        #assuming blob_string is given in this case
                        findings = observe_with_content_regex_signature(blob, signature, blob_string)
                        blob_findings += findings if !findings.empty?
                    end
                else
                    if signature.type == "match"
                        finding = observe_with_match_signature(blob, signature)
                    else
                        finding = observe_with_regex_signature(blob, signature)
                    end
                    blob_findings << finding if !finding.nil?
                end
            end
            return blob_findings
        end

        def self.signatures
            load_signatures! unless @signatures
            @signatures
        end

        def self.load_signatures!
            @signatures = []
            signatures = JSON.load(File.read(SIGNATURES_FILE_PATH))
            validate_signatures!(signatures)
            signatures.each_with_index do |signature|
                @signatures << Signature.new(signature)
            end
        rescue CorruptSignaturesError => e
            raise e
        rescue
            raise CorruptSignaturesError, "Could not parse signature file"
        end

        def self.unload_signatures
            @signatures = []
        end

        def self.custom_signatures?
            File.exist?(CUSTOM_SIGNATURES_FILE_PATH)
        end

        def self.load_custom_signatures!
            signatures = JSON.load(File.read(CUSTOM_SIGNATURES_FILE_PATH))
            validate_signatures!(signatures)
            signatures.each do |signature|
                @signatures << Signature.new(signature)
            end
        rescue CorruptSignaturesError => e
            raise e
        rescue
            raise CorruptSignaturesError, "Could not parse signature file"
        end

        def self.validate_signatures!(signatures)
            if !signatures.is_a?(Array) || signatures.empty?
                fail CorruptSignaturesError,
                "Signature file contains no signatures"
            end
            signatures.each_with_index do |signature, index|
                begin
                    validate_signature!(signature)
                rescue CorruptSignaturesError => e
                    raise CorruptSignaturesError,
                    "Validation failed for Signature ##{index + 1}: #{e.message}"
                end
            end
        end

        def self.validate_signature!(signature)
            validate_signature_keys!(signature)
            validate_signature_type!(signature)
            validate_signature_part!(signature)
        end

        def self.validate_signature_keys!(signature)
            REQUIRED_SIGNATURE_KEYS.each do |key|
                unless signature.key?(key)
                    fail CorruptSignaturesError,
                    "Missing required signature key: #{key}"
                end
            end
        end

        def self.validate_signature_type!(signature)
            unless ALLOWED_TYPES.include?(signature["type"])
                fail CorruptSignaturesError,
                "Invalid signature type: #{signature['type']}"
            end
        end

        def self.validate_signature_part!(signature)
            unless ALLOWED_PARTS.include?(signature["part"])
                fail CorruptSignaturesError,
                "Invalid signature part: #{signature['part']}"
            end
        end

        def self.observe_with_match_signature(blob, signature)
            haystack = blob.send(signature.part.to_sym)
            return unless haystack == signature.pattern
            {
                :caption => signature.caption,
                :description => signature.description,
                :file_name => blob.filename,
                :url => blob.html_url,
                :code_fragment => haystack,
                :part => signature.part,

            }
        end

        def self.observe_with_regex_signature(blob, signature)
            haystack = blob.send(signature.part.to_sym)
            regex = Regexp.new(signature.pattern, Regexp::IGNORECASE)
            return if regex.match(haystack).nil?
            {
                :caption => signature.caption,
                :description => signature.description,
                :file_name => blob.filename,
                :url => blob.html_url,
                :code_fragment => haystack,
                :part => signature.part,

            }
        end

        def self.observe_with_content_regex_signature(blob, signature, blob_string)
            #check extension_regex
            if signature.extension_pattern != nil
                regex = Regexp.new(signature.extension_pattern, Regexp::IGNORECASE)
                return [] if regex.match(blob.extension).nil?
            end

            regex = Regexp.new(signature.pattern, Regexp::IGNORECASE)
            #TODO: check for GITROBIGNORE tag in order to ignore finding
            findings =[]
            blob_string.each_line do |haystack|
                next if regex.match(haystack).nil?
                findings <<
                {
                    :caption => signature.caption,
                    :description => signature.description,
                    :file_name => blob.filename,
                    :url => blob.html_url,
                    :code_fragment => haystack,
                    :part => signature.part

                }
            end
            return findings
        end
    end
end
