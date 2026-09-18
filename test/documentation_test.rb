require "test_helper"
require "uri"

class DocumentationTest < ActiveSupport::TestCase
  ROOT = Pathname.new(File.expand_path("..", __dir__))
  DOCUMENTS = (["README.md", "CHANGELOG.md"] + Dir["docs/**/*.md", base: ROOT]).freeze

  test "documentation links resolve from their new locations" do
    DOCUMENTS.each do |document|
      local_links(document).each do |target|
        file = target.split(/[?#]/, 2).first
        next if file.empty?
        resolved = ROOT.join(File.dirname(document), URI::DEFAULT_PARSER.unescape(file)).cleanpath
        assert resolved.exist?, "#{document}: missing link target #{target}"
      end
    end
  end

  test "every guide audit and reference is discoverable from the documentation index" do
    indexed = local_links("docs/README.md").map { |link| ROOT.join("docs", link.split("#", 2).first).cleanpath }
    DOCUMENTS.grep(%r{\Adocs/}).each do |document|
      next if document == "docs/README.md"
      assert_includes indexed, ROOT.join(document), "Missing index entry for #{document}"
    end
  end

  test "the gem packages the documentation tree and advertises its index" do
    specification = Gem::Specification.load(ROOT.join("beskar.gemspec").to_s)
    assert_equal DOCUMENTS.grep(%r{\Adocs/}).sort, specification.files.grep(%r{\Adocs/.*\.md\z}).sort
    assert_equal "https://github.com/humadroid-io/beskar/blob/master/docs/README.md", specification.metadata["documentation_uri"]
    assert_equal %w[CHANGELOG.md README.md], Dir["*.md", base: ROOT].sort
  end

  test "installer and task documentation pointers resolve in the gem source" do
    paths = %w[lib/generators/beskar/install/install_generator.rb
      lib/generators/beskar/install/templates/initializer.rb.tt lib/tasks/beskar_tasks.rake]
    paths.each do |path|
      ROOT.join(path).read.scan(%r{docs/[a-zA-Z0-9/_-]+\.md}).each do |target|
        assert ROOT.join(target).file?, "#{path}: missing guide #{target}"
      end
    end
  end

  private

  # The docs use inline Markdown links; remote URLs and local anchors need no
  # filesystem lookup. Source links may target directories as well as files.
  def local_links(document)
    ROOT.join(document).read.scan(/!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+[^)]*)?\)/).flatten
      .reject { |target| target.match?(/\A(?:[a-z][a-z0-9+.-]*:|#)/i) }
  end
end
