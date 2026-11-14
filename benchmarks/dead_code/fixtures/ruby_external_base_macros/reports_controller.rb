class ReportsController < ApplicationController
  before_action :load_report, only: [:show]
  after_action :record_view
  helper_method :report_title
  rescue_from ActiveRecord::RecordNotFound, with: :render_missing

  def show
    render plain: @report.title
  end

  def export
    render json: { format: :orphan_format, state: :orphan_state }
  end

  def archive
    head :ok
  end
  private :archive

  private

  def load_report
    @report = Report.find(params[:id])
  end

  def record_view
    @report.touch
  end

  def report_title
    @report.title.upcase
  end

  def render_missing
    head :not_found
  end

  def orphan_filter
    head :forbidden
  end

  def orphan_format
    "csv"
  end
end
