1. How assert works in pytest / test passes
  1. assert [condition], "optional error message"
    - If it passes, nothing happens.
    - if it fails 
      - In normal python, it just has an assertion error with no additive important info
      - In pytest, it gives an error and shows the reason. This is only done where pytest considers the file to be a test file.
2. If a variable is on hold or unavailable and you want to test it, use an if statement with is None
  1. ex: if [variable] is None:
  2. Use `is`, not `==`. None is a singleton and == can be overridden by a class.
  3. The reason this matters (this is the bug that bit me): 0.0 is FALSY. So `if score:`
    treats a real reading of zero as if nothing was reported. Same for `if not score:`.
     "I looked and found nothing" (0.0) and "I never looked" (None) are different facts,
     and only `is None` tells them apart.
  4. Falsy values to watch for: None, 0, 0.0, "", [], {}, False.
3. None has no arithmetic operators
4. Tuples capture values at construction and changing the value of the variable doesnt change the tuple.
5. Tests aren't enough to determine quality code, ensure the least amount of errors by using data structures when needed and keeping as few if/elif branches as possible
  1. Concretely: my 6 tests were green while my formula was wrong. 5 of the 6 only assert
    the decision string, and the bands are wide, so two different weighting schemes both
     passed. Green means "I did not break the properties someone thought to write down",
     not "I built the same thing".
6. Weighted average with a missing term - divide by the sum of the weights you ACTUALLY
  used, not by 1.
  1. Weights: injection 0.35, drift 0.30, anomaly 0.25, threat 0.10.
  2. With anomaly and threat absent: (0.35*80 + 0.30*80) = 52, but that 52 is out of 0.65,
    not out of 100. So 52 / 0.65 = 80. The division is what rescues the score.
  3. Without the division a missing signal silently drags the score toward zero. An 80
    would report as 52 - an attack downgraded from block to hold by a detector that
     simply was not running.
  4. Do NOT split the missing weight evenly between the survivors. That keeps the total at
    1 but flattens their relative importance. Dividing by the sum of present weights
     preserves the 35:30 ratio exactly. (Dividing by 1 - missing weight is the same thing,
     but it silently breaks if the weights in config ever stop summing to 1.)
  5. Open question I still owe an answer to: what should happen if EVERY signal is absent?
    Right now injection and drift are required params so it cannot happen, and the divide
     would be by zero if it could.
7. Rounding before a comparison is a decision, not formatting. round(risk, 1) then testing
  against a threshold means a raw 70.04 becomes 70.0 and lands in the hold band instead of
   block. Decide deliberately whether you round before or after you compare.
8. Replacing branches with a data structure - the actual lesson of combiner.py.
  1. I wrote one branch per combination of present/absent signals. 2 optional signals = 4
    branches; 3 would be 8. Each branch had its own hand-computed fractions.
  2. The original writes no branches per combination. It puts the signals that exist into
    a dict and does the arithmetic once over whatever is in there.
  3. It is NOT about the dict being fast, and not about hashmaps. A list of (name, value)
    pairs would work identically. The point is that "which signals are present" becomes a
     value you can loop over instead of a shape of the program you have to enumerate.
  4. Payoff: combinations I never thought of are handled anyway (the TypeError hole I had
    to add a 4th branch for never existed in the original), and there is one place to be
     right instead of four.
  5. General rule: if I catch myself writing a branch per combination of inputs, the
    combinations probably want to be a collection I filter, not a tree I enumerate.
9. Concurrency
  1. ++**gather**++ always returns the order of the coroutines passed initially.
    1. **gather,** allows for errors to show up first before allowing the other processes to complete. this helps with fixing errors sooner. It still allows the other processes to be comoplete
  2. `return_exceptions=True` :  Allows for the valueError to only come in after all the other processes end so that everything can be shown as completed. **every result might be an exception object instead of a value, so you have to check types yourself.**
  3. `wait_for(coro, timeout)` *— waits for a single coroutine; if the timeout expires it cancels that coroutine (its* `finally` *runs) and raises* `TimeoutError`*. Contrast with* `gather`*, which leaves failed siblings running.*
  4. BaseException
    ─ Exception          ← ordinary problems: ValueError, TypeError, TimeoutError...
    ─ KeyboardInterrupt  ← you pressed Ctrl+C
    ─ SystemExit         ← the program is shutting down
    ─ CancelledError     ← this task has been told to stop
    `except Exception` only catches things in the **Exception** branch. `CancelledError` lives outside it, so `except Exception` walks straight past it.
10. **setattr** -- it turns ++config.timeout = 5++ to ++setattr(config, "timeout", 5)++ 
11. **monkeypatch** -- sets up setattr immediately and automatically undoes it.

