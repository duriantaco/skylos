"""Ruby lexical scopes and source-visible Rails callback ancestry.

All fixtures are parsed statically. Their used/unused labels were fixed before
changing the Ruby visitor, with same-name and no-op override controls.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze


CASES = {
    "block_parameter_outer_call": {
        "source": "class Worker\n  def run\n    [1].each { |normalize| puts normalize }\n    normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "block_parameter_only": {
        "source": "class Worker\n  def run\n    [1].each { |normalize| puts normalize }\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": [],
        "unused": ["Worker#normalize", "Worker#unused"],
    },
    "lambda_parameter_outer_call": {
        "source": "class Worker\n  def run\n    transform = ->(normalize) { normalize + 1 }\n    transform.call(1)\n    normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "rails_inherited_callback": {
        "source": 'class ApplicationController < ActionController::Base\nend\nclass ReportsController < ApplicationController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": ["ReportsController#authenticate"],
        "unused": ["ReportsController#unused"],
    },
    "rails_own_callback_override": {
        "source": 'class ReportsController < ActionController::Base\n  def self.before_action(*args); nil; end\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": [],
        "unused": ["ReportsController#authenticate", "ReportsController#unused"],
    },
    "rails_ancestor_callback_override": {
        "source": 'class ApplicationController < ActionController::Base\n  def self.before_action(*args); nil; end\nend\nclass ReportsController < ApplicationController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": [],
        "unused": ["ReportsController#authenticate", "ReportsController#unused"],
    },
    "nested_block_parameter": {
        "source": "class Worker\n  def run\n    [1].each do |outer|\n      [2].each { |normalize| puts normalize }\n      normalize\n    end\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "block_created_local": {
        "source": "class Worker\n  def run\n    [1].each { normalize = 1; puts normalize }\n    normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "lambda_created_local": {
        "source": "class Worker\n  def run\n    transform = -> { normalize = 1; normalize }\n    transform.call\n    normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "outer_local_survives_parameter_shadow": {
        "source": "class Worker\n  def run\n    normalize = 1\n    [2].each { |normalize| puts normalize }\n    puts normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": [],
        "unused": ["Worker#unused", "Worker#normalize"],
    },
    "method_call_before_assignment": {
        "source": "class Worker\n  def run\n    normalize\n    normalize = 1\n    puts normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "method_parameter_only": {
        "source": "class Worker\n  def run(normalize = 1)\n    puts normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": [],
        "unused": ["Worker#unused", "Worker#normalize"],
    },
    "block_local_declaration": {
        "source": "class Worker\n  def run\n    [1].each { |value; normalize| normalize = value; puts normalize }\n    normalize\n  end\n  private\n  def normalize; 1; end\n  def unused; 2; end\nend\nWorker.new.run\n",
        "used": ["Worker#normalize"],
        "unused": ["Worker#unused"],
    },
    "block_parameter_does_not_replace_outer_receiver": {
        "source": "class First\n  private\n  def helper; 1; end\nend\nclass Other\n  private\n  def helper; 2; end\nend\nclass Runner\n  def run\n    worker = First.new\n    [Other.new].each { |worker| puts worker }\n    worker.send(:helper)\n  end\nend\nRunner.new.run\n",
        "used": ["First#helper"],
        "unused": ["Other#helper"],
    },
    "rails_class_alias": {
        "source": 'class ApplicationController < ActionController::Base\nend\nBaseController = ApplicationController\nclass ReportsController < BaseController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": ["ReportsController#authenticate"],
        "unused": ["ReportsController#unused"],
    },
    "rails_api_inherited": {
        "source": 'class ApplicationController < ActionController::API\nend\nclass ReportsController < ApplicationController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": ["ReportsController#authenticate"],
        "unused": ["ReportsController#unused"],
    },
    "rails_deep_inheritance": {
        "source": 'class ApplicationController < ActionController::Base\nend\nclass ProtectedController < ApplicationController\nend\nclass ReportsController < ProtectedController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": ["ReportsController#authenticate"],
        "unused": ["ReportsController#unused"],
    },
    "rails_alias_ancestor_override": {
        "source": 'class ApplicationController < ActionController::Base\n  def self.before_action(*args); nil; end\nend\nBaseController = ApplicationController\nclass ReportsController < BaseController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": [],
        "unused": ["ReportsController#unused", "ReportsController#authenticate"],
    },
    "rails_alias_rebound_custom_base": {
        "source": 'class ApplicationController < ActionController::Base\nend\nclass Plain\n  def self.before_action(*args); nil; end\nend\nBaseController = ApplicationController\nBaseController = Plain\nclass ReportsController < BaseController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": [],
        "unused": ["ReportsController#unused", "ReportsController#authenticate"],
    },
    "rails_local_provider_shadow": {
        "source": 'module ActionController\n  class Base\n    def self.before_action(*args); nil; end\n  end\nend\nclass ApplicationController < ActionController::Base\nend\nclass ReportsController < ApplicationController\n  before_action :authenticate\n  def index; "ok"; end\n  private\n  def authenticate; true; end\n  def unused; false; end\nend\n',
        "used": [],
        "unused": ["ReportsController#unused", "ReportsController#authenticate"],
    },
    "rails_scoped_namespace_alias": {
        "source": 'class ApplicationController < ActionController::Base\nend\nmodule Web\n  AC = ActionController\n  class ReportsController < AC::Base\n    before_action :authenticate\n    def index; "ok"; end\n    private\n    def authenticate; true; end\n    def unused; false; end\n  end\nend\n',
        "used": ["Web.ReportsController#authenticate"],
        "unused": ["Web.ReportsController#unused"],
    },
    "deferred_method_uses_initialized_class_alias": {
        "source": "class Worker\n  private\n  def helper; 1; end\n  def unused; 2; end\nend\nclass Runner\n  def run\n    AliasWorker.new.send(:helper)\n  end\nend\nAliasWorker = Worker\nRunner.new.run\n",
        "used": ["Worker#helper"],
        "unused": ["Worker#unused"],
    },
}


@pytest.mark.parametrize("case_id", CASES)
def test_ruby_scopes_and_callback_lineage_keep_exact_methods(tmp_path, case_id):
    case = CASES[case_id]
    source = tmp_path / "main.rb"
    source.write_text(case["source"])
    report = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            grep_verify=False,
            enable_danger=False,
            enable_quality=False,
            enable_secrets=False,
            enable_sca=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            custom_rules_data=[],
        )
    )
    assert report["analysis_summary"]["total_files"] == 1
    assert report["analysis_summary"]["languages"] == {"Ruby": 1}
    assert report.get("analysis_errors") == []
    definitions = report["definitions"]
    unused = report.get("unused_functions", [])
    assert {row["full_name"] for row in unused} == set(case["unused"])
    for symbol in case["used"] + case["unused"]:
        definition = definitions[symbol]
        assert definition["name"] == symbol
        assert Path(definition["file"]) == source
        assert definition["line"] > 0
        assert definition["dead"] is (symbol in case["unused"])
        for row in unused:
            if row["full_name"] == symbol:
                assert row["line"] == definition["line"]
                assert Path(row["file"]) == source
                assert row["listing"]["listed"] is True


def test_alias_resolution_limit_is_explicit_unknown_not_clean_safety():
    from skylos.visitors.languages.ruby.core import RubyCore

    source = (
        "class ApplicationController < ActionController::Base\nend\nAlias0 = ApplicationController\n"
        + "".join(f"Alias{i} = Alias{i - 1}\n" for i in range(1, 80))
        + "class ReportsController < Alias79\n  before_action :authenticate\n  private\n  def authenticate; true; end\nend\n"
    )
    core = RubyCore("main.rb", source.encode())
    core.scan()
    assert "ReportsController" not in core.rails_classes
    assert any(
        "alias resolution limit" in item["reason"] for item in core.dynamic_dispatch
    )
    assert "ReportsController#authenticate" in {name for name, _ in core.refs}


def test_late_alias_does_not_attest_an_earlier_superclass_binding():
    from skylos.visitors.languages.ruby.core import RubyCore

    # Standalone Ruby would reject the uninitialized ControllerBase. A later
    # assignment cannot prove which external binding an earlier class used.
    source = "class ApplicationController < ActionController::Base\nend\nclass ReportsController < ControllerBase\n  before_action :authenticate\n  private\n  def authenticate; true; end\nend\nControllerBase = ApplicationController\n"
    core = RubyCore("main.rb", source.encode())
    core.scan()
    assert "ReportsController" not in core.rails_classes
