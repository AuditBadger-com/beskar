module Beskar
  class AdministrativeActionsController < ApplicationController
    before_action { response.headers["Cache-Control"] = "no-store" }

    def index
      records = AdministrativeAction.order(id: :desc)
      records = records.where(target_type: "BannedIp", target_id: params[:target_id]) if params[:target_id].present?
      @pagination = paginate(records)
      @administrative_actions = @pagination[:records]
    end

    def show
      @administrative_action = AdministrativeAction.find(params[:id])
    end
  end
end
