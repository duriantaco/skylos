class TextCodec
  def publish(value)
    process(value)
  end

  private

  def process(value)
    value.strip
  end
end

class BinaryCodec
  private

  def process(value)
    value.reverse
  end
end

TextCodec.new.publish("ready")
BinaryCodec.new
