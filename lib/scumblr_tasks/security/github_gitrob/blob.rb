
module Gitrob
    class AbstractBlob
        SHA_REGEX = /[a-f0-9]{40}/
        TEST_BLOB_INDICATORS = %w[test spec fixture mock stub fake demo sample dummy].freeze

        attr_accessor :repository, :owner, :content, :html_url
        attr_reader :path

        def initialize(data)
            @path = data['path']
            @size = data['size']
            @sha = data['sha']
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

        def url_line_part(line)
            raise NotImplementedError, "#{self.class.name}#area is an abstract method."
        end

        def should_observe_path
            raise NotImplementedError, "#{self.class.name}#area is an abstract method."
        end
    end

    class DiffBlob < AbstractBlob
        def initialize(data)
            super(data)
            @status = data['status']
            @content = interpret_diff(data['content'])
        end

        def interpret_diff(patch)
            return [] if patch.nil? || patch.blank?
            lines = patch.lines

            start_line_right = /\+(\d*)/.match(lines.first)[0].to_i

            right = lines.reject { |l| l.start_with?('-', '@@') }

            content = right.map.with_index(start_line_right) { |line, index| Gitrob::Line.new(index, line) }.select { |l| l.content.start_with?('+') }.each { |l| l.content[0] = '' }
            content
        end

        def url_line_part(line)
            "R#{line.line_number}"
        end

        def should_observe_path
            @status == "added" || @status == "renamed"
        end
    end

    class Blob < AbstractBlob
        def initialize(data)
            super(data)
            @content = data['content'].each_line.map.with_index(1) { |line, index| Gitrob::Line.new(index, line) }.reject { |h| h.content.blank? }
        end

        def url_line_part(line)
            "#L#{line.line_number}"
        end

        def should_observe_path
            true
        end
    end

    class Line
        attr_accessor :line_number, :content
        def initialize(line_number, content)
            @line_number = line_number
            @content = content
        end
    end
end
