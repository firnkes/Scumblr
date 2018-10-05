
module Gitrob
    class AbstractBlob
        SHA_REGEX = /[a-f0-9]{40}/
        TEST_BLOB_INDICATORS = %w[test spec fixture mock stub fake demo sample].freeze

        attr_accessor :repository, :owner, :content, :html_url
        attr_reader :path

        def initialize(data)
            @path = data['path']
            @size = data['size']
            @sha = data['sha']
            @content = data['content']
            @html_url = data['url']
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

        def url_line_token
            raise NotImplementedError.new("#{self.class.name}#area is anabstract method.")
        end

        def should_observe_path
            raise NotImplementedError.new("#{self.class.name}#area is anabstract method.")
        end
    end

    class DiffBlob < AbstractBlob

        def initialize(data)
            data['content'] = get_diff(data['content'])
            super(data)
            @modified = data['modified']
        end

        def get_diff(patch)
            patch = '' if patch.nil?
            patch.split.select { |line| line.start_with?('-', '+') }.join("\n")
        end

        def url_line_token
            "R"
        end

        def should_observe_path
            return !@modified
        end
    end

    class Blob < AbstractBlob
        def url_line_token
            "#L"
        end

        def should_observe_path
            return true
        end
    end
end
