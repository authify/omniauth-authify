# frozen_string_literal: true

# Small helpers for the bash-driven smoke tests. Usage:
#
#   ruby consent_fields.rb <html-file> <approve|deny> <output-file>
#   ruby parse_query.rb "<url>"            # prints key=value per line
#
# Used by run_smoke_tests.sh, keeping the smoke harness in the project's
# language.
require "uri"

case ARGV[0]
when "consent_fields"
  html = File.read(ARGV[1])
  forms = html.scan(%r{<form.*?</form>}m)
  needle = %(name="approve" value="#{ARGV[2]}")
  form = forms.find { |f| f.include?(needle) }
  abort "FAIL: no #{ARGV[2]} form in consent page" unless form

  fields = form.scan(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>/)
  File.write(ARGV[3], URI.encode_www_form(fields))
when "parse_query"
  query = URI.parse(ARGV[1]).query.to_s
  URI.decode_www_form(query).each { |key, value| puts "#{key}=#{value}" }
else
  abort "usage: smoke_helper.rb consent_fields <file> <true|false> <out> | parse_query <url>"
end
