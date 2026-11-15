class Formatter
  def initialize(prefix)
    @prefix = pad(prefix)
  end

  def format(value)
    "#{@prefix}#{value}"
  end

  private

  def pad(text)
    "#{text} "
  end

  def initialize_defaults
    @prefix = ""
  end

  def orphan_pad(text)
    " #{text}"
  end
end
