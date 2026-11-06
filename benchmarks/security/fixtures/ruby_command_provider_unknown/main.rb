module Kernel
  def self.system(*arguments)
    arguments
  end
end

Kernel.system("sh", "-c", ARGV[0])
