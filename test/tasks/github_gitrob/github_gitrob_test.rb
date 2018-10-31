require_relative '../../test_helper'

class GithubGitrobAnalyzerTest < ActiveSupport::TestCase


    test 'task execute user' do
        github_search_fixture = Task.where(id: 100).first
        github_search_fixture.perform_task

        # Return 2 results from test github org
        puts(github_search_fixture.metadata[:current_results].to_json)
        assert_equal(2, github_search_fixture.metadata[:current_results][:created].count)

        # Check vuln count is correct
        assert_equal(2, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].count)
        # Check that the vulnerablity was opened
        assert_equal('New', Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].first['status'])

        # Check vuln count is correct
        assert_equal(0, Result.where(url: 'https://github.com/scumblrtestdata/repo1').first.metadata['vulnerabilities'].count)

        #
        # Vulnerablity Counter Assertions
        #

        # assert 2 open issues
        assert_equal(2, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['state']['open'])

        assert_equal(2, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['task_id']['100'])
    end

    test 'execute task repo' do
        github_search_fixture = Task.where(id: 101).first
        github_search_fixture.perform_task

        assert_equal(1, github_search_fixture.metadata[:current_results][:created].count)

        # Check vuln count is correct
        assert_equal(2, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].count)
        # Check that the vulnerablity was opened
        assert_equal('New', Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].first['status'])

        #
        # Vulnerablity Counter Assertions
        #

        # assert 2 open issues
        assert_equal(2, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['state']['open'])

        # assert task id
        assert_equal(2, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['task_id']['101'])
    end

    test 'execute task repo deep search' do
        github_search_fixture = Task.where(id: 102).first
        github_search_fixture.perform_task

        # Return 1 results from test github org
        assert_equal(1, github_search_fixture.metadata[:current_results][:created].count)

        # Check vuln count is correct
        assert_equal(3, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].count)
        # Check that the vulnerablity was opened
        assert_equal('New', Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].first['status'])

        #
        # Vulnerablity Counter Assertions
        #

        # assert 3 open issues
        assert_equal(3, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['state']['open'])
        # assert task id
        assert_equal(3, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['task_id']['102'])
    end


    test 'execute task repo all branches' do
        github_search_fixture = Task.where(id: 103).first
        github_search_fixture.perform_task

        # Return 1 results from test github org
        assert_equal(1, github_search_fixture.metadata[:current_results][:created].count)

        # Check vuln count is correct
        assert_equal(3, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].count)
        # Check that the vulnerablity was opened
        assert_equal('New', Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].first['status'])

        #
        # Vulnerablity Counter Assertions
        #

        # assert 3 open issues
        assert_equal(3, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['state']['open'])
        # assert task id
        assert_equal(3, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['task_id']['103'])
    end

    test 'execute task repo test branch' do
        github_search_fixture = Task.where(id: 104).first
        github_search_fixture.perform_task

        assert_equal(1, github_search_fixture.metadata[:current_results][:created].count)

        # Check vuln count is correct
        assert_equal(1, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].count)
        # Check that the vulnerablity was opened
        assert_equal('New', Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerabilities'].first['status'])

        #
        # Vulnerablity Counter Assertions
        #

        # assert 1 open issues
        assert_equal(1, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['state']['open'])
        # assert task id
        assert_equal(1, Result.where(url: 'https://github.com/scumblrtestdata/repo2').first.metadata['vulnerability_count']['task_id']['104'])
    end

end
