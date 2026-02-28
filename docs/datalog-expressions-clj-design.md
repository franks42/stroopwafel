# Datalog Expressions — Clojure-Native Design

## Motivation

Stroopwafel v0.4.0 can only match fact patterns. It cannot express guards like
"time less than expiry" or "amount at most 100". This is the #1 real-world gap
blocking time-based token expiry, amount limits, and string prefix matching.

Biscuit uses a custom expression syntax (`$time < 2026-03-01T00:00:00Z`).
We use **Clojure-native forms** with whitelisted functions instead, inspired by
Datascript's `built_ins.cljc` model. This gives us familiar syntax, no parser
to write, and safe evaluation.

---

## 1. Syntax: `:when` Guard Clauses

Guards are a `:when` key on rules, checks, and policies — a vector of Clojure
forms. All must return truthy. Variables (`?`-prefixed symbols) are substituted
from pattern-matching bindings.

### Rules

Rules are already quoted, so variables are symbols:

```clojure
:rules '[{:id   :active-user
          :head [:active ?u]
          :body [[:user ?u] [:last-seen ?u ?t] [:time ?now]]
          :when [(> ?t (- ?now 86400000))]}]
```

### Checks

Checks must be quoted when using variables:

```clojure
:checks '[{:id    :check-expiry
           :query [[:time ?t]]
           :when  [(< ?t 1709251200000)]}]
```

### Policies

```clojure
:policies '[{:kind :allow
             :query [[:amount ?a]]
             :when  [(<= ?a 100)]}]
```

---

## 2. `:let` Bindings (Computed Variables)

Optional bindings evaluated after pattern matching, before `:when` guards.
Each entry is `[?var expression]`. Useful for rules that need computed values
in the head.

```clojure
'{:id   :total-cost
  :head [:total-cost ?item ?total]
  :body [[:price ?item ?p] [:tax-rate ?item ?rate]]
  :let  [[?total (* ?p (+ 1 ?rate))]]
  :when [(< ?total 1000)]}
```

Evaluation order: `eval-body` -> `:let` -> `:when` -> `instantiate`

---

## 3. Substitution Logic (NOT Macro Expansion)

Runtime variable substitution + function application. Three-step process:

1. **Walk** the expression form recursively
2. **Replace** `?`-prefixed symbols with their values from the environment
3. **Apply** the resolved function (from built-in registry) to evaluated args

### Example

With env = `{?t 500, ?limit 1000}`:

```
(< ?t ?limit)
  -> substitute vars: (< 500 1000)
  -> resolve `<` from built-in-fns registry
  -> (apply < [500 1000])
  -> true
```

### Nested Forms

Evaluated inside-out (standard evaluation order):

```
(and (>= ?t 0) (< ?t ?limit))
  -> substitute vars: (and (>= 500 0) (< 500 1000))
  -> eval (>= 500 0) -> true
  -> eval (< 500 1000) -> true
  -> eval (and true true) -> true
```

### Why Not Macro Expansion

Macros transform code at compile time. Our expressions are data (vectors/lists
inside EDN maps) evaluated at runtime with a specific environment. More
accurately: it's a **mini-interpreter** over Clojure forms, similar to how
Datascript's `-call-fn` (`query.cljc:480-511`) builds closures per tuple.

### Unbound Variables

If a variable in a `:when` expression is not bound by the `:query`/`:body`
patterns, `eval-expr` throws with a clear error message including the variable
name and the available bindings.

---

## 4. Whitelisted Built-in Functions

Security-critical: only registered functions can be called. No `eval`, no
`resolve`, no namespace lookup, no I/O. Modeled after Datascript's `query-fns`
map (`built_ins.cljc:81-99`) but scoped to authorization use cases.

| Category | Functions |
|----------|-----------|
| Comparison | `<` `>` `<=` `>=` `=` `not=` |
| Arithmetic | `+` `-` `*` `/` `mod` `rem` |
| String | `str/starts-with?` `str/ends-with?` `str/includes?` `str/lower-case` `str/upper-case` `count` `subs` `str` |
| Logic | `not` `and` `or` |
| Collections | `contains?` `empty?` `count` |
| Type | `string?` `number?` `keyword?` `int?` `nil?` `some?` |
| Regex | `re-matches` `re-find` |

### Resolution Comparison

| | Datascript | Stroopwafel |
|--|-----------|-------------|
| Resolution order | built-ins -> query inputs -> `clojure.core/resolve` | **built-ins only** |
| Namespace lookup | Yes (fallback) | **No** (security boundary) |
| ~Functions | ~100+ (DB-specific like `get-else`, `missing?`) | ~35 (authorization-focused) |

The registry is extensible — additional functions can be added as needed.

---

## 5. Evaluation Timing in the Pipeline

### Current Pipeline

```
eval-body(patterns, facts) -> [{:env :proof :origin} ...]
  |
  v
fire-rule: instantiate(head, env) -> derived fact
eval-check: any match? -> pass/fail
```

### New Pipeline

```
eval-body(patterns, facts) -> [{:env :proof :origin} ...]
  |
  v
eval-let(let-bindings, env) -> extended env       <-- NEW
  |
  v
eval-when(when-guards, env) -> true/false          <-- NEW (filter)
  |
  v
fire-rule: instantiate(head, env) -> derived fact
eval-check: any match? -> pass/fail
```

The guards act as a **post-pattern-matching filter**. Variables are fully bound
after `eval-body` completes — all patterns must match before any guard runs.
This is identical to Datascript's `filter-by-pred` (`query.cljc:518-531`)
which filters tuples after join, not during.

---

## 6. Rich Examples

### 1. Time-Based Token Expiry (the #1 use case)

```clojure
;; Authority issues token with expiry check
(sut/issue {:facts  [[:user "alice"] [:right "alice" :read "/data"]]
            :checks '[{:id    :check-expiry
                       :query [[:time ?t]]
                       :when  [(< ?t 1709251200000)]}]}  ;; expires March 2024
           {:private-key (:priv kp)})

;; Authorizer provides current time
(sut/evaluate token
  :authorizer {:facts    [[:time (System/currentTimeMillis)]]
               :policies [{:kind :allow
                           :query [[:right "alice" :read "/data"]]}]})
```

### 2. Amount Limit

```clojure
:checks '[{:id    :max-transfer
           :query [[:transfer-amount ?a]]
           :when  [(<= ?a 10000)]}]
```

### 3. String Prefix Matching

```clojure
:checks '[{:id    :public-only
           :query [[:resource ?r]]
           :when  [(str/starts-with? ?r "/public/")]}]
```

### 4. Compound Guard (Time Window)

```clojure
:checks '[{:id    :valid-window
           :query [[:time ?t]]
           :when  [(>= ?t 1704067200000)    ;; not before Jan 2024
                   (< ?t 1735689600000)]}]  ;; not after Jan 2025
```

### 5. Arithmetic in Guards

```clojure
:checks '[{:id    :budget-check
           :query [[:qty ?q] [:unit-price ?p] [:budget ?b]]
           :when  [(<= (* ?q ?p) ?b)]}]
```

### 6. Rule with Computed Value via `:let`

```clojure
:rules '[{:id   :compute-total
          :head [:invoice-total ?item ?total]
          :body [[:line-item ?item ?qty ?price]]
          :let  [[?total (* ?qty ?price)]]
          :when [(> ?total 0)]}]
```

### 7. Deny Rule with Guard (Reject if Expired)

```clojure
:checks '[{:id    :reject-expired
           :kind  :reject
           :query [[:time ?t] [:expiry ?exp]]
           :when  [(>= ?t ?exp)]}]
```

### 8. Policy with Guard

```clojure
:policies '[{:kind  :allow
             :query [[:role ?u :admin] [:time ?t]
                     [:admin-hours-start ?s] [:admin-hours-end ?e]]
             :when  [(>= ?t ?s) (< ?t ?e)]}]
```

---

## Implementation Plan

### New Functions (additive, in `datalog.clj`)

**`built-in-fns`** — Map of `symbol -> function`. ~35 entries. Uses
`clojure.string` functions directly (already required as `str`).

**`eval-expr [form env]`** — Recursive expression evaluator:
- `(variable? form)` -> lookup in env, throw if unbound
- `(sequential? form)` with elements -> `[fn & args]`, resolve fn from
  `built-in-fns`, recursively eval args, `apply`
- otherwise -> return literal

**`eval-when [when-clauses env]`** — `(every? #(eval-expr % env) clauses)`.
Returns true when `when-clauses` is nil or empty (backward compat).

**`eval-let [let-bindings env]`** — Sequential reduce: for each `[?var expr]`,
evaluate `expr` in current env and bind result to `?var`. Returns extended env.
Returns env unchanged when `let-bindings` is nil.

### Integration Points

**`fire-rule`**: Destructure `{guards :when, let-bindings :let}` from rule.
After `eval-body`, for each state: apply `eval-let`, then filter by
`eval-when`, then `instantiate`. Backward compatible — nil `:when`/`:let`
means no filtering.

**`eval-check`**: Extract `:when` from check map. After `eval-body query`,
filter results by `eval-when`. Existing checks without `:when` unaffected.

**`eval-policy`**: Same pattern as `eval-check`.
