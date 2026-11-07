class ApplicationController < ActionController::Base
end
class ReportsController < ApplicationController
  before_action :authenticate
  def index; "ok"; end
  private
  def authenticate; true; end
  def unused; false; end
end
