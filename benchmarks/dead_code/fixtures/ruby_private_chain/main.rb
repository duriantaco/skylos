class Formatter
  def publish(value)
    render(value)
  end

  private

  def render(value)
    normalize(value)
  end

  def normalize(value)
    value.strip
  end

  def snapshot(value)
    value.reverse
  end
end

Formatter.new.publish("ready")
