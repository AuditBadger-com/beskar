module Beskar
  module Services
    # Centralizes adapter-specific JSON expressions. Values are always bound;
    # table/column names come from the model, never request parameters.
    class EventSearch
      def initialize(relation)
        @relation = relation
        @connection = relation.klass.connection
      end

      def search(term)
        match(term, %w[ip_address user_agent attempted_email event_type].map { |name| column(name) } + [metadata_text])
      end

      def email(term)
        # Match the model's legacy fallback, not unrelated text in metadata.
        match(term, ["COALESCE(#{column("attempted_email")}, #{legacy_email})"])
      end

      private

      def match(term, expressions)
        return @relation unless term.is_a?(String) && term.present?
        value = RequestContext.text(term, limit: 256).downcase
        pattern = "%#{@relation.klass.sanitize_sql_like(value, "!")}%"
        predicates = expressions.map { |expression| "LOWER(#{expression}) LIKE ? ESCAPE '!'" }
        @relation.where(predicates.join(" OR "), *Array.new(expressions.length, pattern))
      end

      def column(name)
        "#{@connection.quote_table_name(@relation.klass.table_name)}.#{@connection.quote_column_name(name)}"
      end

      def mysql?
        %w[Mysql2 Trilogy].include?(@connection.adapter_name)
      end

      def metadata_text
        "CAST(#{column("metadata")} AS #{mysql? ? "CHAR" : "TEXT"})"
      end

      def legacy_email
        metadata = column("metadata")
        case @connection.adapter_name
        when "PostgreSQL"
          "(#{metadata} ->> 'attempted_email')"
        when "Mysql2", "Trilogy"
          extracted = "JSON_EXTRACT(#{metadata}, '$.attempted_email')"
          "CASE WHEN JSON_TYPE(#{extracted}) = 'NULL' THEN NULL ELSE JSON_UNQUOTE(#{extracted}) END"
        when "SQLite"
          "json_extract(#{metadata}, '$.attempted_email')"
        else
          raise ArgumentError, "Beskar email search does not support this database adapter"
        end
      end
    end
  end
end
