require 'uri'
require 'net/http'
require 'json'
require 'rest-client'
require 'time'
require 'byebug'
require 'digest'

BINARY_EXTENSIONS_FILE_PATH = File.join(File.dirname(__FILE__), '../../helpers/binary_extensions.json')
BINARY_EXTENSIONS = JSON.parse(File.read(BINARY_EXTENSIONS_FILE_PATH))

MAX_RETRY_DOWNLOAD_BLOB = 3

class ScumblrTask::GithubGitrobAnalyzer < ScumblrTask::Base
    def self.task_type_name
        'Github Gitrob Code Search'
    end

    def self.task_category
        'Security'
    end

    def self.description
        "Searches one or several github repositories for secrets using gitrob's search functionality."
    end

    def self.options
        {
        github_oauth_token: { name: 'Github OAuth Token',
                              description: "Setting this token provides the access needed to search private Github organizations or repos. If not set only public repos can be searched. Important: The token is requried to perform search on the official github endpoint. ('https://api.github.com')",
                              required: false },
        severity: { name: 'Finding Severity',
                    description: 'Set severity to either observation, high, medium, or low',
                    required: true,
                    type: :choice,
                    default: :observation,
                    choices: %i[observation high medium low] },
        user: { name: 'Scope to User Or Organization',
                description: 'Limit search to an Organization or User.',
                required: false,
                type: :string },
        repo: { name: 'Scope to Repository',
                description: "Limit search to a Repository. Full name with owner of repository is required. Schema ':owner/:repo'",
                required: false,
                type: :string },
        github_api_endpoint: { name: 'Github Endpoint',
                               description: 'Configurable endpoint for Github Enterprise deployments',
                               required: true,
                               type: :choice,
                               default: 'https://github.infra.hana.ondemand.com/api/v3',
                               choices: ['https://github.infra.hana.ondemand.com/api/v3',
                                         'https://github.wdf.sap.corp/api/v3',
                                         'https://api.github.com'] },
        custom_github_api_endpoint: { name: 'Custom Github Endpoint',
                                      description: "Custom configurable endpoint for Github Enterprise deployments. Overwrites other endpoint configurations. Must point to an api endpoint, e.g.
        'https://github.wdf.sap.corp/api/v3'",
                                      required: false,
                                      type: :string },
        deep_search: {  name: 'Deep Search',
                        description: 'Searches all commits of a branch.',
                        type: :boolean,
                        default: false}
    }
    end

    def initialize(options = {})
        super

        @github_oauth_token = @options[:github_oauth_token].to_s.strip.empty? ? nil : @options[:github_oauth_token].to_s.strip
        @github_api_endpoint = @options[:custom_github_api_endpoint].to_s.strip.empty? ? @options[:github_api_endpoint].to_s : @options[:custom_github_api_endpoint].to_s.strip.chomp('/')

        @search_type = nil
        @search_scope = nil
        # End of remove
        if @options[:key_suffix].present?
            @key_suffix = '_' + @options[:key_suffix].to_s.strip
            puts "A key suffix was provided: #{@key_suffix}."
        end


        # Check that they actually specified a repo or org.
        unless @options[:user].present? || @options[:repo].present?
            raise ScumblrTask::TaskException, 'No user, repo, or org provided.'
            return
        end

        # Only let one type of search be defined
        if @options[:user].present? && @options[:repo].present?
            create_event('Both user/originzation and repo provided, defaulting to user/originzation.', "Warn")
            @search_scope = @options[:user]
            @search_type = :user
        # Append any repos to the search scope
        elsif @options[:repo].present?
            @search_scope = @options[:repo]
            @search_type = :repo
        elsif @options[:user].present?
            @search_scope = @options[:user]
            @search_type = :user
        end

        @deep_search = @options[:deep_search]
    end

    def run
        client_manager = Gitrob::Github::ClientManager.new(
            access_tokens: [@github_oauth_token],
            endpoint: @github_api_endpoint,
            ssl: { verify: true }
        )

        if @search_type == :user
            data_manager = Gitrob::Github::DataManager.new(@search_scope, client_manager)
            analyze_user(data_manager)
        else
            data_manager = Gitrob::Github::DataManager.new([], client_manager)
            analyze_repository(@search_scope, data_manager)
        end

        []
    rescue ::Github::Error::Unauthorized
        raise ScumblrTask::TaskException, 'Unauthorized. Check if the Github OAuth Token is valid!'
        return
    rescue ::Gitrob::Github::DataManager::ApiLimitReachedError
        raise ScumblrTask::TaskException, 'API rate Limit Reached. Setting OAuth Token could help.'
        return
    end

    def analyze_repository(search_scope, data_manager)
        owner_repo = search_scope.split('/', 2)
        raise ScumblrTask::TaskException, "Full name of repository is required. Schema: ':owner/:repo'" if owner_repo.length < 2

        repo = data_manager.get_repository(owner_repo[0], owner_repo[1])
        raise ScumblrTask::TaskException, 'Repository not found.' if repo.nil?

        blobs = []
        if @deep_search.to_i == 1
            blobs = create_blobs_for_history(repo, data_manager)
        else
            blobs = create_blobs_for_current_state(repo, data_manager)
        end

        results = analyze_blobs(blobs)
        report_results(results, repo)
    end

    def analyze_user(data_manager)
        data_manager.gather_owners
        raise ScumblrTask::TaskException, 'No user/orga found.' if data_manager.owners.empty?

        data_manager.gather_repositories
        raise ScumblrTask::TaskException, 'No repositories for user/orga found.' if data_manager.repositories.empty?

        data_manager.owners.each do |owner|
            data_manager.repositories_for_owner(owner).each do |repo|
                analyze_repository(repo.full_name, data_manager)
            end
        end
    end

    def create_blobs_for_current_state (repo, data_manager)
        blobs = []
        data_manager.blobs_for_repository(repo).each do |blob|
            blob_string = data_manager.blob_string_for_blob_repo(blob)
            allowed_columns = Gitrob::Models::Blob.allowed_columns
            data = blob.select { |k, _v| allowed_columns.include?(k.to_sym) }
            data['content'] = blob_string
            data['modified'] = False
            data['is_diff'] = False

            blobs.push(create_blob(data, repo))
        end
        blobs
    end

    def create_blobs_for_history(repo, data_manager)
        blobs = []
        commits = data_manager.commits_for_repository(repo)

        commits.each do |c|
            commit = data_manager.get_commit_details(repo, c)
            commit['files'].each do |file|
                data = {
                    'path' => file['filename'],
                    'size' => commit['stats']['total'],
                    'sha' => commit['sha'],
                    'content' => get_diff(file['patch']),
                    'modified' => file['status'] == 'modified',
                    'is_diff' => true
                }
                md5 = Digest::MD5.hexdigest(data['path'])
                data['url'] = commit['html_url'] + "#diff-#{md5}"
                blobs.push(create_blob(data, repo))
            end
        end
        blobs
    end



    def create_blob(data, repo)
        blob = Gitrob::Models::Blob.new(data)
        blob.repository = repo
        blob.owner = repo['owner']['login']
        return blob
    end

    def analyze_blobs(blobs)
        results = []
        blobs.each do |blob|
            result = Gitrob::BlobObserver.observe(blob)
            results += result unless result.empty?
        end
        results
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

        if @options[:key_suffix].present?
            vuln.key_suffix = @options[:key_suffix]
        end

        vuln.source = 'github_event'
        vuln.task_id = @options[:_self].id.to_s
        vuln.severity = @options[:severity]

        begin
            vuln.name = result[:caption]
            vuln.type = "#{result[:part]} match"
            vuln.file_name = result[:file_name]
            vuln.url = result[:url]
            vuln.code_fragment = result[:code_fragment]
            vuln.match_location = result[:part]
            vuln.source_code_file = result[:file_name]
            vuln.source_code_line = result[:line].present? ? result[:line].to_s : nil
            vuln.details = "#{result[:caption]} #{result[:description]}"
            vuln.regex = result[:regex].present? ? result[:regex] : nil
            return vuln
        rescue StandardError => e
            create_event("Unable to add metadata.\n\n. Exception: #{e.message}\n#{e.backtrace}", 'Warn')
        end
    end

    def upsert_vulnarabilities(vulnerabilities, repo)
        metadata = metadata(repo)
        res = Result.where({url: repo[:html_url].downcase, user: @options[:_user]}).first
        if res.present?
            res.update_vulnerabilities(vulnerabilities, {:isolate_vulnerabilities => true})
            res.metadata['repository_data'] = metadata['repository_data']
            res.add_tags(@options[:tags]) if @options[:tags].present?
            res.save!
        else
            github_result = Result.new(url: repo[:html_url].downcase, title: repo[:full_name].to_s + ' (Github)', domain: 'github', metadata: { 'repository_data' => metadata['repository_data']})
            github_result.user = @options[:_user]
            github_result.add_tags(@options[:tags]) if @options[:tags].present?
            github_result.save!
            github_result.update_vulnerabilities(vulnerabilities, {:isolate_vulnerabilities => true})
            task_result = TaskResult.new({:task_id=>@options[:_self].id.to_s, :result_id=> github_result.id})
            task_result.save
        end
    end

    def metadata(repo)
        search_metadata ||= {}
        search_metadata['repository_data'] ||= {}
        search_metadata['repository_data']['name'] = repo[:full_name]
        search_metadata['repository_data']['slug'] = repo[:full_name]
        search_metadata['repository_data']['project'] = repo.owner[:login]
        search_metadata['repository_data']['project_name'] = repo.owner[:login]
        search_metadata['repository_data']['project_type'] = repo.owner[:type] == 'User' ? 'User' : 'Project'
        search_metadata['repository_data']['private'] = repo[:private]
        search_metadata['repository_data']['source'] = 'github'
        search_metadata['repository_data']['link'] = repo[:html_url]
        search_metadata['repository_data']['repository_host'] = @github_api_endpoint.gsub(/\Ahttps?:\/\//, '').gsub(/\/.+/, '')
        search_metadata
    end
end

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

module Gitrob
    module Github
        class DataManager
            attr_reader :client_manager,
                        :unknown_logins,
                        :owners,
                        :repositories

            class ApiLimitReachedError < StandardError; end

            def initialize(login, client_manager)
                @login = login
                @client_manager = client_manager
                @unknown_logins = []
                @owners = []
                @repositories = []
                @repositories_for_owners = {}
            end

            def gather_owners
                return unless owner = get_owner(@login)
                @owners << owner
                @repositories_for_owners[owner['login']] = []
                return unless owner['type'] == 'Organization'
                get_members(owner) if owner['type'] == 'Organization'

                @owners = @owners.uniq { |o| o['login'] }
            end

            def gather_repositories
                owners.each do |owner|
                    repositories = get_repositories(owner)
                    save_repositories(owner, repositories)
                    yield owner, repositories if block_given?
                end
            end

            def repositories_for_owner(owner)
                @repositories_for_owners[owner['login']]
            end

            def get_repository(user, repo)
                github_client do |client|
                    client.repos.get(
                        user: user,
                        repo: repo
                    )
                end
            rescue ::Github::Error::NotFound
                return nil
            end

            def blob_string_for_blob_repo(blob)
                download_blob(blob)
            rescue ::Github::Error::Forbidden => e
                # Hidden GitHub feature?
                raise e unless e.message.include?('403 Repository access blocked')
                []
            rescue ::Github::Error::NotFound => e
                []
            rescue ::Github::Error::ServiceError => e
                raise e unless e.message.include?('409 Git Repository is empty')
                []
            end

            def blobs_for_repository(repository)
                get_blobs(repository)
            rescue ::Github::Error::Forbidden => e
                # Hidden GitHub feature?
                raise e unless e.message.include?('403 Repository access blocked')
                []
            rescue ::Github::Error::NotFound
                []
            rescue ::Github::Error::ServiceError => e
                raise e unless e.message.include?('409 Git Repository is empty')
                []
            end

            def commits_for_repository(repository)
                get_commits(repository)
            rescue ::Github::Error::Forbidden => e
                # Hidden GitHub feature?
                raise e unless e.message.include?('403 Repository access blocked')
                []
            rescue ::Github::Error::NotFound
                []
            rescue ::Github::Error::ServiceError => e
                raise e unless e.message.include?('409 Git Repository is empty')
                []
            end

            def get_commit_details(repo, commit)
                get_commit(repo, commit)
            rescue ::Github::Error::Forbidden => e
                # Hidden GitHub feature?
                raise e unless e.message.include?('403 Repository access blocked')
                []
            rescue ::Github::Error::NotFound
                []
            rescue ::Github::Error::ServiceError => e
                raise e unless e.message.include?('409 Git Repository is empty')
                []
            end

            private

            def get_owner(login)
                github_client do |client|
                    client.users.get(user: login)
                end
            rescue ::Github::Error::NotFound
                @unknown_logins << login
                nil
            end

            def get_members(org)
                github_client do |client|
                    client.orgs.members.list(org_name: org['login']) do |owner|
                        owner = get_owner(owner['login'])
                        @owners << owner
                        @repositories_for_owners[owner['login']] = []
                    end
                end
            end

            def get_repositories(owner)
                if owner['type'] == 'Organization'
                    github_client do |client|
                        client.repos.list(org: owner['login'], type: 'sources')
                    end
                else
                    github_client do |client|
                        client.repos.list(
                            user: owner['login']
                        )
                    end
                end
            end

            def download_blob(blob)
                # check for binary extension. This check cannot
                # be always correct, because the list of binaries
                # cannot be complete. Thus, the second binary Check
                # after downloading the file is still needed.
                return '' if binary_extension?(blob.path)


                utf8blob = ''

                github_client do |client|
                    for i in 1..MAX_RETRY_DOWNLOAD_BLOB
                        begin
                            b64blob = client.get_request(blob.url)['content']
                            utf8blob = Base64.decode64(b64blob).encode(
                                Encoding.find('UTF-8'),
                                invalid: :replace, undef: :replace, replace: ''
                            )
                        rescue
                            if i ==  MAX_RETRY_DOWNLOAD_BLOB
                                raise
                            end
                        else
                            next
                        end
                    end
                end

                # binary files create encoding issues and it makes no sense to use regex on them
                # so just ignore them
                utf8blob = '' if binary?(utf8blob)
                utf8blob
            end

            def get_blobs(repository, sha = nil)
                url = "/repos/#{repository[:full_name]}/git/trees/#{repository[:default_branch]}"
                url = url + "/#{sha}" unless sha.nil?
                resp =
                github_client do |client|
                    client.get_request(
                        url,
                        ::Github::ParamsHash.new(recursive: 1)
                    )
                end
                if resp['truncated']
                    resp = github_client do |client|
                                client.get_request(
                                    url,
                                    ::Github::ParamsHash.new(recursive: 0)
                                )
                    end
                    if resp['truncated']
                        raise ScumblrTask::TaskException, 'Could not receive all files from github. Too many files for rest api request.'
                    end
                    blobs = resp['tree'].select { |b| b['type'] == 'blob' }
                    resp['tree'].select{ |b| b['type'] == 'tree' }.each do |t|
                        blobs += get_blobs(repository, t['sha'])
                    end
                    return blobs
                else
                    return resp['tree'].select { |b| b['type'] == 'blob' }
                end
            end

            def get_commits(repo)
                for i in 1..MAX_RETRY_DOWNLOAD_BLOB
                    begin
                        resp =
                        github_client do |client|
                            client.repos.commits.list(repo['owner']['login'], repo['name'])
                        end
                        return resp.map{|c| c['sha']}.compact
                    rescue
                        if i == MAX_RETRY_DOWNLOAD_BLOB
                            raise
                        end
                    else
                        next
                    end
                end
            end

            def get_commit(repo, commit)
                for i in 1..MAX_RETRY_DOWNLOAD_BLOB
                    begin
                        resp =
                        github_client do |client|
                            client.repos.commits.get(repo['owner']['login'], repo['name'], commit)
                        end
                        return resp
                    rescue
                        if i == MAX_RETRY_DOWNLOAD_BLOB
                            raise
                        end
                    else
                        next
                    end
                end
            end

            def github_client
                client = @client_manager.sample
                yield client
            rescue ::Github::Error::Forbidden => e
                if e.message.include?('API rate limit exceeded')
                    raise ApiLimitReachedError
                else
                    raise e
                end
            rescue ::Github::Error::Unauthorized
                raise
            end

            def save_repositories(owner, repositories)
                @repositories += repositories
                @repositories_for_owners[owner['login']] = repositories
            end
        end
    end
end

module Gitrob
    module Models
        class Blob
            SHA_REGEX = /[a-f0-9]{40}/
            TEST_BLOB_INDICATORS = %w[test spec fixture mock stub fake demo sample].freeze

            attr_accessor :repository, :owner, :content, :html_url, :modified, :is_diff
            attr_reader :path

            def initialize(data)
                @path = data['path']
                @size = data['size']
                @sha = data['sha']
                @content = data['content']
                @html_url = data['url']
                @modified = data['modified']
                @is_diff = data['is_diff']
            end

            def self.allowed_columns
                %i[path size sha content url]
            end

            def validate
                super
                validates_presence %i[path size sha]
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
        end
    end
end

module Gitrob
    class BlobObserver
        SIGNATURES_FILE_PATH = File.expand_path(
            '/etc/gitrob_signatures/signatures.json', __FILE__
        )

        FALSE_POSITIVE_SIGNATURES_FILE_PATH = File.expand_path(
            '/etc/gitrob_signatures/false_positive_signatures.json', __FILE__
        )

        REQUIRED_SIGNATURE_KEYS = %w[part type pattern caption description].freeze
        ALLOWED_TYPES = %w[regex match].freeze
        ALLOWED_PARTS = %w[path filename extension content].freeze

        class Signature < OpenStruct
        end
        class CorruptSignaturesError < StandardError
        end

        def self.observe(blob)
            blob_findings = []
            signatures.each do |signature|
                if signature.part == 'content'
                    if blob.content && !blob.content.empty?
                        findings = observe_with_content_regex_signature(blob, signature)
                        blob_findings += findings unless findings.empty?
                    end
                else
                     next if blob.modified # prevents multiple detections of same file name

                     if signature.type == 'match'
                        finding = observe_with_match_signature(blob, signature)
                     else
                        finding = observe_with_regex_signature(blob, signature)
                     end
                    blob_findings << finding unless finding.nil?
                end
            end
            blob_findings
        end

        def self.signatures
            @signatures = load_signatures!(SIGNATURES_FILE_PATH) unless @signatures
            @signatures
        end

        def self.false_positive_signatures
            @false_positive_signatures = load_signatures!(FALSE_POSITIVE_SIGNATURES_FILE_PATH) unless @false_positive_signatures
            @false_positive_signatures
        end

        def self.load_signatures!(file_path)
            signatures = []
            _signatures = JSON.load(File.read(file_path))
            validate_signatures!(_signatures)
            _signatures.each do |signature|
                signatures << Signature.new(signature)
            end
            signatures
        rescue CorruptSignaturesError => e
            raise e
        rescue StandardError
            raise CorruptSignaturesError, 'Could not parse signature file'
        end

        def self.unload_signatures
            @signatures = []
        end

        def self.validate_signatures!(signatures)
            if !signatures.is_a?(Array) || signatures.empty?
                raise CorruptSignaturesError,
                      'Signature file contains no signatures'
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
                    raise CorruptSignaturesError,
                          "Missing required signature key: #{key}"
                end
            end
        end

        def self.validate_signature_type!(signature)
            unless ALLOWED_TYPES.include?(signature['type'])
                raise CorruptSignaturesError,
                      "Invalid signature type: #{signature['type']}"
            end
        end

        def self.validate_signature_part!(signature)
            unless ALLOWED_PARTS.include?(signature['part'])
                raise CorruptSignaturesError,
                      "Invalid signature part: #{signature['part']}"
            end
        end

        def self.observe_with_match_signature(blob, signature)
            haystack = blob.send(signature.part.to_sym)
            return unless haystack == signature.pattern
            {
                caption: signature.caption,
                description: signature.description,
                file_name: blob.filename,
                url: blob.html_url,
                code_fragment: haystack,
                part: signature.part

            }
        end

        def self.observe_with_regex_signature(blob, signature)
            haystack = blob.send(signature.part.to_sym)
            regex = Regexp.new(signature.pattern, Regexp::IGNORECASE)
            return if regex.match(haystack).nil?
            {
                caption: signature.caption,
                description: signature.description,
                file_name: blob.filename,
                url: blob.html_url,
                code_fragment: haystack,
                part: signature.part,
                regex: regex
            }
        end

        def self.observe_with_content_regex_signature(blob, signature)
            # check extension_regex
            unless signature.extension_pattern.nil?
                regex = Regexp.new(signature.extension_pattern, Regexp::IGNORECASE)
                return [] if regex.match(blob.extension).nil?
            end

            regex = Regexp.new(signature.pattern, Regexp::IGNORECASE)
            findings = []
            line_part = blob.is_diff ? "R" : "#L"
            blob.content.each_line.with_index(1) do |haystack, index|
                next unless regex.match(haystack)
                next if false_positive?(haystack, blob.extension)
                findings <<
                    {
                        caption: signature.caption,
                        description: signature.description,
                        file_name: blob.filename,
                        url: blob.html_url + "#{line_part}#{index}",
                        code_fragment: haystack,
                        part: signature.part,
                        line: index,
                        regex: regex
                    }
            end
            findings
        end
    end
end

require 'filemagic'
def binary?(content)
    fm = FileMagic.new(FileMagic::MAGIC_MIME)
    fm.buffer(content) !~ /^text\//
ensure
    fm.close
end

def binary_extension?(path)
    extension = File.extname(File.basename(path)).strip.downcase[1..-1]
    BINARY_EXTENSIONS.include? extension
end

def false_positive?(haystack, extension)
    false_positive_signatures.each do |signature|
        unless signature.extension_pattern.nil?
            regex = Regexp.new(signature.extension_pattern, Regexp::IGNORECASE)
            next unless regex.match(extension.nil? ? "" : extension)
        end
        regex = Regexp.new(signature.pattern, Regexp::IGNORECASE)
        return true if regex.match(haystack)
    end
    false
end

def get_diff(patch)
    if patch.nil?
        patch = ""
    end
    patch.split().select{|line| line.start_with?('-','+')}.join("\n")
end
