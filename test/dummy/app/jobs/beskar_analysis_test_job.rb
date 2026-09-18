class BeskarAnalysisTestJob < ActiveJob::Base
  self.queue_adapter = :test

  def perform(user_type:, user_id:, event_type:)
    # A host-owned job fixture; the engine supplies identity, not credentials.
  end
end
