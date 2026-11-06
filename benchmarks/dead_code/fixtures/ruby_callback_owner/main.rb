class PageController < ActionController::Base
  before_action :authorize

  def show
    render_text
  end

  private

  def authorize
    puts "authorize"
  end

  def render_text
    puts "page"
  end

  def preview
    puts "preview"
  end
end

class PlainHandler
  def self.before_action(name)
    name
  end

  before_action :prepare

  private

  def prepare
    puts "plain"
  end
end

PageController.action(:show)
PlainHandler.new
