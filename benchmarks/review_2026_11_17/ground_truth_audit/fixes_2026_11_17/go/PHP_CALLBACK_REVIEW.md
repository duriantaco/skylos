# Independent review and hardening of concurrent PHP callback support

The concurrent patch correctly binds literal `[$this, 'method']` arguments through a private same-class helper whose plain `callable` parameter is invoked. Owner/method privacy, positional arguments, dynamic mutation, indirect aliases and first-class-callable creation are checked. Independent review found that syntax-only body traversal also treated callbacks after unconditional returns or inside constant-dead branches as invocation evidence, which could conceal genuinely unused private callbacks.

The patch now computes potentially executable callback occurrences for sequential blocks, literal boolean branches, returning branches, fixed-false loops, short-circuit/ternary expressions and infinite loops. It preserves calls in unknown branches and in loop initializers that actually execute. Generator, goto, switch/match and try bodies decline this bounded helper proof; their control/dispatch semantics are not guessed. Existing mutation checks remain conservative. No PHP application code is executed.

Focused paired controls cover dead-after-return, dead literal if/elseif arms, returning alternatives, loop conditions/updates, generator bodies and live/unknown guards. Results: **67 focused callback tests passed**, and **611 full PHP tests passed**. Logs are `php_callable_review_tests.log` and `php_full_tests_final.log`.

The reviewed callback feature is relevant to the requested noise reduction and is suitable to include with this reachability hardening and its tests. The source proof remains a bounded static reference model; it does not claim arbitrary interprocedural condition evaluation or automatic-removal safety.
