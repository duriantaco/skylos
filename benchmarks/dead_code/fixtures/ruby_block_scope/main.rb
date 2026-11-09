class Worker
  def run
    [1].each { |normalize| puts normalize }
    normalize
  end
  private
  def normalize; 1; end
  def unused; 2; end
end
Worker.new.run
