
module Gitrob
    class BlobObserver
        SIGNATURES_FILE_PATH = File.join(File.dirname(__FILE__),
            '../../../../config/signatures/signatures.json',
        )

        FALSE_POSITIVE_SIGNATURES_FILE_PATH = File.join(File.dirname(__FILE__),
            '../../../../config/signatures/false_positive_signatures.json',
        )

        REQUIRED_SIGNATURE_KEYS = %w[part type pattern caption description].freeze
        ALLOWED_TYPES = %w[regex match].freeze
        ALLOWED_PARTS = %w[path filename extension content].freeze

        SKIP_TEST_BLOBS = false

        class Signature < OpenStruct
        end
        class CorruptSignaturesError < StandardError
        end

        def self.observe(blob)
            blob_findings = []
            return blob_findings if SKIP_TEST_BLOBS && blob.test_blob?
            signatures.each do |signature|
                if signature.part == 'content'
                    if blob.content && !blob.content.empty?
                        findings = observe_with_content_regex_signature(blob, signature)
                        blob_findings += findings unless findings.empty?
                    end
                else
                     next if !blob.should_observe_path # prevents multiple detections of same file name

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
            blob.content.each do |line|
                haystack, index = line.content, line.line_number
                next unless regex.match(haystack)
                next if false_positive?(haystack, blob.extension)

                line_part = blob.url_line_part(line)
                findings <<
                    {
                        caption: signature.caption,
                        description: signature.description,
                        file_name: blob.filename,
                        url: blob.html_url + "#{line_part}",
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
