require 'json'


BINARY_EXTENSIONS_FILE_PATH = File.join(File.dirname(__FILE__), '../../../helpers/binary_extensions.json')
BINARY_EXTENSIONS = JSON.parse(File.read(BINARY_EXTENSIONS_FILE_PATH))

MAX_RETRY_DOWNLOAD_BLOB = 3


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
                owner = nil
                retry_github_call{
                    return unless owner = get_owner(@login)
                }
                @owners << owner
                @repositories_for_owners[owner['login']] = []
                return unless owner['type'] == 'Organization'
                retry_github_call{ get_members(owner) } if owner['type'] == 'Organization'

                @owners = @owners.uniq { |o| o['login'] }
            end

            def gather_repositories
                owners.each do |owner|
                    repositories = retry_github_call { get_repositories(owner) }
                    save_repositories(owner, repositories)
                    yield owner, repositories if block_given?
                end
            end

            def repositories_for_owner(owner)
                @repositories_for_owners[owner['login']]
            end

            def get_repository(user, repo)
                retry_github_call{
                    begin
                    github_client do |client|
                        client.repos.get(
                            user: user,
                            repo: repo
                        )
                    end
                    rescue ::Github::Error::NotFound
                        return nil
                    end
                }
            end

            def get_branches(user, repo)
                retry_github_call{
                    github_client do |client|
                        client.repos.branches.list(
                            user: user,
                            repo: repo
                        ).map{|b| b.name}.compact
                    end
                }
            end

            def blob_string_for_blob_repo(blob)
                try_github_api_call{ download_blob(blob) }
            end

            def blobs_for_repository(repository, branch)
                try_github_api_call{ get_blobs(repository, branch) }
            end

            def commits_for_repository(repository, branch)
                try_github_api_call{ get_commits(repository, branch) }
            end

            def get_commit_details(repo, commit)
                try_github_api_call{ get_commit(repo, commit) }
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

                retry_github_call{
                    github_client do |client|
                            b64blob = client.get_request(blob.url)['content']
                            utf8blob = Base64.decode64(b64blob).encode(
                                Encoding.find('UTF-8'),
                                invalid: :replace, undef: :replace, replace: ''
                            )
                        end
                }

                # binary files create encoding issues and it makes no sense to use regex on them
                # so just ignore them
                utf8blob = '' if binary?(utf8blob)
                utf8blob
            end

            def get_blobs(repository, branch, sha = nil)
                url = "/repos/#{repository[:full_name]}/git/trees/#{branch}"
                url = url + "/#{sha}" unless sha.nil?
                resp = retry_github_call {
                github_client do |client|
                    client.get_request(
                        url,
                        ::Github::ParamsHash.new(recursive: 1)
                    )
                end }
                if resp['truncated']
                    resp = retry_github_call{ github_client do |client|
                                client.get_request(
                                    url,
                                    ::Github::ParamsHash.new(recursive: 0)
                                )
                    end }
                    if resp['truncated']
                        raise ScumblrTask::TaskException, 'Could not receive all files from github. Too many files for rest api request.'
                    end
                    blobs = resp['tree'].select { |b| b['type'] == 'blob' }
                    resp['tree'].select{ |b| b['type'] == 'tree' }.each do |t|
                        blobs += get_blobs(repository, branch, t['sha'])
                    end
                    return blobs
                else
                    return resp['tree'].select { |b| b['type'] == 'blob' }
                end
            end

            def get_commits(repo, branch)
                retry_github_call{
                        resp =
                        github_client do |client|
                            client.repos.commits.list(repo['owner']['login'], repo['name'], sha: branch)
                        end
                        return resp.map{|c| c['sha']}.compact
                }
            end

            def get_commit(repo, commit)
                retry_github_call {
                    resp =
                    github_client do |client|
                        client.repos.commits.get(repo['owner']['login'], repo['name'], commit)
                    end
                    return resp
                }
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

def try_github_api_call
    yield
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

def retry_github_call
    begin
        retries ||= 0
        yield
    rescue
        retries += 1
        raise if (retries > MAX_RETRY_DOWNLOAD_BLOB)
        Rails.logger.debug("Github call retry number : #{retries}")
        sleep(2**retries)
        retry
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
