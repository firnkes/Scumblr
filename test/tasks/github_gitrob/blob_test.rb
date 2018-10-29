require 'active_support/test_case'
require_relative '../../../lib/scumblr_tasks/security/github_gitrob/blob'

class DiffBlobTest < ActiveSupport::TestCase
    def setup
        @blob = Gitrob::DiffBlob.new(
            'path' => 'a/b/c.rb',
            'size' => 5,
            'sha' => 'asdewasd',
            'url' => 'github/a/b/c',
            'status' => 'added'
        )
    end

    def test_should_observe_path
        assert @blob.should_observe_path
    end

    def test_should_not_observe_path_modified
        @blob.status = 'modified'
        assert !@blob.should_observe_path
    end

    def test_should_not_observe_path_deleted
        @blob.status = 'deleted'
        assert !@blob.should_observe_path
    end

    def test_should_not_observe_path_renamed
        @blob.status = 'renamed'
        assert @blob.should_observe_path
    end

    def test_url_line_part_start_first
        @blob.content = "@@ -1,5 +1,5 @@\n # Scumblr\n-This is a fork of: https://github.com/Netflix-Skunkworks/Scumblr/wiki  \n+This is a fork of: https://github.com/Netflix-Skunkworks/Scumblr\n Use this scanner to search one or several github repositories for credentials like passwords or private keys.\n \n See https://github.wdf.sap.corp/CPSecurity/scumblr-docker-compose on how to configure and run it."
        assert_equal 'R2', @blob.url_line_part(@blob.content[0])
    end

    def test_url_line_part_start_not_first
        @blob.content = "@@ -87,7 +87,7 @@ class Application < Rails::Application\n \n     # Set Time.zone default to the specified zone and make Active Record auto-convert to this zone.\n     # Run \"rake -D time\" for a list of tasks for finding time zone names. Default is UTC.\n-    config.time_zone = 'Pacific Time (US & Canada)'\n+    config.time_zone = 'Berlin'\n \n \n     config.to_prepare do"
        assert_equal 'R90', @blob.url_line_part(@blob.content[0])
    end

    def test_url_line_part_multiple
        @blob.content = "@@ -18,8 +18,9 @@\n   # In the development environment your application's code is reloaded on\n   # every request. This slows down response time but is perfect for development\n   # since you don't have to restart the web server when you make code changes.\n-  config.cache_classes = false\n-  #config.cache_classes = true\n+  # config.cache_classes = false\n+  config.cache_classes = true\n+\n   config.active_record.raise_in_transactional_callbacks = true\n   config.lograge.enabled = true\n   config.lograge.custom_options = lambda do |event|\n@@ -43,11 +44,11 @@\n   #Force raising callback errors\n   config.active_record.raise_in_transactional_callbacks = true\n \n-  config.eager_load = false\n-  #config.eager_load = true\n+  #config.eager_load = false\n+  config.eager_load = true\n \n   # Show full error reports and disable caching\n-  config.consider_all_requests_local       = true\n+  config.consider_all_requests_local       = false\n   config.action_controller.perform_caching = true\n \n   # Don't care if the mailer can't send\n@@ -71,7 +72,7 @@\n   #config.active_record.auto_explain_threshold_in_seconds = 0.5\n \n   # Do not compress assets\n-  config.assets.compress = false\n+  config.assets.compress = true\n   config.assets.compile = true\n \n   # Expands the lines which load the assets"
        assert_equal 'R21', @blob.url_line_part(@blob.content[0])
        assert_equal 'R22', @blob.url_line_part(@blob.content[1])
        assert_equal 'R23', @blob.url_line_part(@blob.content[2])
        assert_equal 'R47', @blob.url_line_part(@blob.content[3])
        assert_equal 'R48', @blob.url_line_part(@blob.content[4])
        assert_equal 'R51', @blob.url_line_part(@blob.content[5])
        assert_equal 'R75', @blob.url_line_part(@blob.content[6])
    end

    def test_init_content
        @blob = Gitrob::DiffBlob.new(
            'path' => 'a/b/c.rb',
            'size' => 5,
            'sha' => 'asdewasd',
            'url' => 'github/a/b/c',
            'content' => "@@ -1,5 +1,5 @@\n # Scumblr\n-This is a fork of: https://github.com/Netflix-Skunkworks/Scumblr/wiki  \n+This is a fork of: https://github.com/Netflix-Skunkworks/Scumblr\n Use this scanner to search one or several github repositories for credentials like passwords or private keys.\n \n See https://github.wdf.sap.corp/CPSecurity/scumblr-docker-compose on how to configure and run it."
        )
        assert_equal 1, @blob.content.length
        assert_equal 'This is a fork of: https://github.com/Netflix-Skunkworks/Scumblr', @blob.content[0].content
    end
end

class BlobTest < ActiveSupport::TestCase
    def setup
        @blob = Gitrob::Blob.new(
            'path' => 'a/b/c.rb',
            'size' => 5,
            'sha' => 'asdewasd',
            'url' => 'github/a/b/c'
        )
    end

    def test_not_test_blob
        assert !@blob.test_blob?
    end

    def test_blob_in_path
        @blob.path = 'a/test/c.rb'
        assert @blob.test_blob?
    end

    def test_blob_in_extension
        @blob.path = 'a/b/c.dummy'
        assert @blob.test_blob?
    end

    def test_blob_in_name
        @blob.path = 'a/b/dummy.rb'
        assert @blob.test_blob?
    end

    def test_extension
        assert_equal 'rb', @blob.extension
    end

    def test_filename
        assert_equal 'c.rb', @blob.filename
    end

    def test_should_observe_path
        assert @blob.should_observe_path
    end

    def test_url_line_part_first
        @blob.content = "line1\n line2 \n line3\n"
        assert_equal '#L1', @blob.url_line_part(@blob.content[0])
    end

    def test_url_line_part_second
        @blob.content = "line1\n line2 \n line3\n"
        assert_equal '#L2', @blob.url_line_part(@blob.content[1])
    end

    def test_url_line_part_last
        @blob.content = "line1\n line2 \n line3\n"
        assert_equal '#L3', @blob.url_line_part(@blob.content[2])
    end

    def test_init_content
        @blob = Gitrob::Blob.new(
            'path' => 'a/b/c.rb',
            'size' => 5,
            'sha' => 'asdewasd',
            'url' => 'github/a/b/c',
            'content' => "a\nb\n"
        )
        assert_equal 2, @blob.content.length
        assert_equal 'a', @blob.content[0].content
    end
end
