class Report < ApplicationRecord
  validate :title_present
  before_save :normalize_title
  validates :slug, presence: true, if: :sluggable?

  private

  def title_present
    errors.add(:title, "missing") if title.to_s.empty?
  end

  def normalize_title
    self.title = title.to_s.strip
  end

  def sluggable?
    title.to_s.length > 3
  end

  def orphan_callback
    self.title = nil
  end
end

class PlainRegistry
  def self.before_save(name)
    name
  end

  before_save :snapshot

  private

  def snapshot
    "plain"
  end
end
