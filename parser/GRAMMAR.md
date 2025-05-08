# Parser Grammar

This document describes the currently supported Datalog grammar.

## Term

Represents a Datalog type, can be one of: parameter, variable, integer, string, date, bytes, boolean, or set.

- parameter is delimited by curly brackets: `{param}`. Those are replaced by actual values before evaluation.
- variable is prefixed with a `$` sign followed by a string or an unsigned 32bit base-10 integer,  e.g. `$0` or `$variable1`
- integer is any base-10 int64
- string is any utf8 character sequence, between double quotes, e.g. `"/path/to/file.txt"`. A double-quote may be included if preceded by a backslash, `\"`
- date is RFC3339 encoded, e.g. `2006-01-02T15:04:05Z`
- bytes is an hexadecimal encoded string, prefixed with a `hex:` sequence
- boolean is either `true` or `false`
- set is a sequence of any of the above types, except variable, between brackets, e.g. `["file1", "file2"]` (sets cannot be nested)

## Predicate

A predicate is a list of terms, grouped under a name in the form `Name(Term0, Term1, ..., TermN)` , e.g. `parent("a", "b")`.

## Constraints

Constraints allows performing checks on a variable, below is the list of available operations by type and their expected format.

### Boolean

- Equal: `$b == true`
- Not equal: `$b != false`
- Negation: `!$b`
- And / Or: `$b || $c && $d`

### Integer

- Equal: `$i == 1`
- Not equal: `$i != 1`
- Greater than: `$i > 1`
- Greater than or equal: `$i >= 1`
- Less than: `$i < 1`
- Less than or equal: `$i <= 1`
- Arithmetic (`*`, `/`, `+`, `-`)
- Bitwise (`&`, `|`, `^`)

###  String

- Equal: `$s == "abc"`
- Not equal: `$s != "abc"`
- Starts with: `$s.starts_with("abc")`
- Ends with: `$s.ends_with("abc")`
- Regular expression: `$s.matches("^abc\s+def$") `
- Contains: `$s.contains("abc")`
- Length: `$s.length()`

### Date

- Equal: `$date == "2006-01-02T15:04:05Z07:00"`
- Not equal: `$date != "2006-01-02T15:04:05Z07:00"`
- Before (strict): `$date < "2006-01-02T15:04:05Z07:00"`
- Before: `$date <= "2006-01-02T15:04:05Z07:00"`
- After (strict): `$date > "2006-01-02T15:04:05Z07:00"`
- Before: `$date <= "2006-01-02T15:04:05Z07:00"`

### Bytes

- Equal: `$b == "hex:3df97fb5"`
- Not equal: `$b != "hex:3df97fb5"`
- Length: `$b.length()`

### Set

- Equal: `$set == ["a", "b"]`
- Not equal: `$set != ["a", "b"]`
- Contains (element membership): `$set.contains("a")`
- Contains (set inclusion): `$set.contains([a])`
- Union: `$set.union(["a"])`
- Intersection: `$set.intersection(["a"])`
- Length: `$set.length()`

### Operators precedence

The operators have the following precedence (highest to lowest):


| Operators                        | Associativity   |
|----------------------------------|-----------------|
| `!` (prefix)                     | not associative |
| `*`, `/`                         | left-associative |
| `+`, `-`                         | left-associative |
| `&`                              | left-associative |
| `\|`                             | left-associative |
| `^`                              | left-associative |
| `>`, `>=`, `<`, `<=`, `==`, `!=` | not associative |
| `&&`                             | left-associative |
| `\|\|`                           | left-associative |

Parentheses can be used to force precedence (or to make it explicit).


## Fact

A fact is a single predicate that does not contain any variables, e.g. `right("file1.txt", "read")`.

# Rule

A rule is formed from a head, a body, and a list of constraints.
The head is a single predicate, the body is a list of predicates or constraints. Variables present in the head and in constraints must be introduced by predicates in the body.

It has the format: `Head <- (predicate, constraint)+`.

e.g. `right($file, "read") <- resource($file), owner($user, $file), $user == "username", $file.starts_with("/home/username")`

# Check

A check starts with `check if`, followed by one or more rule bodies, separated with ` or `.

# Policy

A policy starts with either `allow if` or `deny if`, followed by one or more rule bodies, separated with ` or `.
