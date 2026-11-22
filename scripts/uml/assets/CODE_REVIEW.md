# A practical code review

Start with a concrete behavior: for a particular input or action, what should happen, and what must remain unchanged?

1. Follow the entry point into the changed function, its callers, and the helpers it uses. Read enough surrounding code to understand the contract.
2. Compare before and after. Consider boundary inputs, errors, shared state, compatibility, and unnecessary complexity.
3. Read the tests as carefully as the implementation. Check that assertions would detect broken behavior, then run the relevant checks. A static call link does not establish test coverage.
4. For each finding, record the location, triggering case, consequence, and useful fix or regression test. State the reviewed scope and remaining uncertainty.

This emphasis on design, behavior, context, and meaningful tests follows [Google's review guidance](https://google.github.io/eng-practices/review/reviewer/looking-for.html).

Use AI to explain unfamiliar code and suggest concerns. Verify its claims against source and tests: it can miss defects and report problems that are not real. Review and test suggested changes before accepting them. See [GitHub's application card](https://docs.github.com/en/copilot/responsible-use/agents).

## Using this map

- Click a function for a plain-English description, inputs, return values, effects, source, and connected-function explanations.
- Descriptions marked **Explained from source** have been written from the implementation and are tied to its source hash. Other descriptions identify whether they came from docstrings or structural source facts. Those are reading aids, not a correctness verdict.
- **Review local changes** compares the working tree with `HEAD`; it does not cover the entire branch's pull-request diff.
- Listed tests are static pointers from a bounded search through up to three calls. The viewer does not execute them or measure coverage.
- Source order and graph arrows do not prove runtime execution order. Conditional paths, dynamic dispatch, and external calls can require further investigation.
- **Prepare a deeper review request** creates text you can copy into your coding-agent conversation. It does not call a model or upload source.

Everything remains personal under the ignored `/UML/` folder.
