require 'uri'
require 'net/http'
require 'json'
require 'rest-client'
require 'time'
require 'byebug'
require 'digest'

require_relative  'github_gitrob/blob'
require_relative  'github_gitrob/blob_observer'
require_relative  'github_gitrob/client_manager'
require_relative  'github_gitrob/data_manager'

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
            branch: { name: 'Scope to Branch',
                    description: "Set branch to be searched. If not set, default branch of repository is used. Has no effect if scope is not a single repository.",
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
                                          description: "Custom configurable endpoint for Github Enterprise deployments. Overwrites other endpoint configurations. Must point to an api endpoint, e.g.      'https://github.wdf.sap.corp/api/v3'",
                                          required: false,
                                          type: :string },
            deep_search: { name: 'Deep Search',
                           description: 'Searches all commits of a branch. Increases the task run time.',
                           type: :boolean,
                           default: false }
        }
    end

    def initialize(options = {})
        super

        @github_oauth_token = @options[:github_oauth_token].to_s.strip.empty? ? nil : @options[:github_oauth_token].to_s.strip
        @github_api_endpoint = @options[:custom_github_api_endpoint].to_s.strip.empty? ? @options[:github_api_endpoint].to_s : @options[:custom_github_api_endpoint].to_s.strip.chomp('/')

        @search_type = nil
        @search_scope = nil
        @branch = nil
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
            create_event('Both user/originzation and repo provided, defaulting to user/originzation.', 'Warn')
            @search_scope = @options[:user]
            @search_type = :user
            # Append any repos to the search scope
        elsif @options[:repo].present?
            @search_scope = @options[:repo]
            @search_type = :repo
            @branch = @options[:branch] if @options[:branch].present?
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
            analyze_user(@deep_search, data_manager)
        else
            data_manager = Gitrob::Github::DataManager.new([], client_manager)
            analyze_repository(@search_scope, @deep_search, data_manager)
        end

        []
    rescue ::Github::Error::Unauthorized
        raise ScumblrTask::TaskException, 'Unauthorized. Check if the Github OAuth Token is valid!'
        return
    rescue ::Gitrob::Github::DataManager::ApiLimitReachedError
        raise ScumblrTask::TaskException, 'API rate Limit Reached. Setting OAuth Token could help.'
        return
    end

    def analyze_repository(repository, deep_search, data_manager)
        owner_repo = repository.split('/', 2)
        raise ScumblrTask::TaskException, "Full name of repository is required. Schema: ':owner/:repo'" if owner_repo.length < 2

        repo = data_manager.get_repository(owner_repo[0], owner_repo[1])
        raise ScumblrTask::TaskException, 'Repository not found.' if repo.nil?

        branch = repo.default_branch
        if !@branch.nil?
            branches = data_manager.get_branches(owner_repo[0], owner_repo[1])
            if !branches.select{|b| b.name == @branch}.empty?
                branch = @branch
            else
                raise ScumblrTask::TaskException, 'Branch not found.'
            end
        end

        blobs = []
        blobs = if deep_search.to_i == 1
                    create_blobs_for_history(repo, branch, data_manager)
                else
                    create_blobs_for_current_state(repo, branch, data_manager)
                end

        results = observe_blobs(blobs)
        report_results(results, repo)
    end

    def analyze_user(deep_search, data_manager)
        data_manager.gather_owners
        raise ScumblrTask::TaskException, 'No user/orga found.' if data_manager.owners.empty?

        data_manager.gather_repositories
        raise ScumblrTask::TaskException, 'No repositories for user/orga found.' if data_manager.repositories.empty?

        data_manager.owners.each do |owner|
            data_manager.repositories_for_owner(owner).each do |repo|
                analyze_repository(repo.full_name, deep_search, data_manager)
            end
        end
    end

    def create_blobs_for_current_state(repo, branch, data_manager)
        blobs = []
        data_manager.blobs_for_repository(repo, branch).each do |data|
            blob_string = data_manager.blob_string_for_blob_repo(data)
            data['content'] = blob_string
            data['url'] = "#{repo.html_url}/blob/#{branch}/#{data['path']}"

            blob = Gitrob::Blob.new(data)
            blob.repository = repo
            blob.owner = repo['owner']['login']

            blobs.push(blob)
        end
        blobs
    end

    def create_blobs_for_history(repo, branch, data_manager)
        blobs = []
        commits = data_manager.commits_for_repository(repo, branch)

        commits.each do |c|
            commit = data_manager.get_commit_details(repo, c)
            commit['files'].each do |file|
                data = {
                    'path' => file['filename'],
                    'size' => commit['stats']['total'],
                    'sha' => commit['sha'],
                    'content' => file['patch'],
                    'status' => file['status']
                }
                md5 = Digest::MD5.hexdigest(data['path'])
                data['url'] = commit['html_url'] + "#diff-#{md5}"

                blob = Gitrob::DiffBlob.new(data)
                blob.repository = repo
                blob.owner = repo['owner']['login']

                blobs.push(blob)
            end
        end
        blobs
    end

    def observe_blobs(blobs)
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
        res = Result.where(url: repo[:html_url].downcase, user: @options[:_user]).first
        if res.present?
            res.update_vulnerabilities(vulnerabilities, isolate_vulnerabilities: true)
            res.metadata['repository_data'] = metadata['repository_data']
            res.add_tags(@options[:tags]) if @options[:tags].present?
            res.save!
        else
            github_result = Result.new(url: repo[:html_url].downcase, title: repo[:full_name].to_s + ' (Github)', domain: 'github', metadata: { 'repository_data' => metadata['repository_data'] })
            github_result.user = @options[:_user]
            github_result.add_tags(@options[:tags]) if @options[:tags].present?
            github_result.save!
            github_result.update_vulnerabilities(vulnerabilities, isolate_vulnerabilities: true)
            task_result = TaskResult.new(task_id: @options[:_self].id.to_s, result_id: github_result.id)
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
