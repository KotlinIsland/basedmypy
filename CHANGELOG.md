# Basedmypy Changelog

## [Unreleased]
### Added
- Deprecate python 3.7 support (#457)
### Enhancements
- Removed `Any` from the typings for `re.Match` group functions. (#459)
### Fixes
- Fix unsafe variance note (#452)

## [1.8.0]
### Added
- `Intersection` type (#357)

## [1.7.0]
### Added
- `ignore-missing-py-typed` to use types even if there is no `py.typed` (#337)
### Fixes
- Errors regarding inferred functions didn't have a note (#394)
- Type ignored calls to incomplete functions left a phantom note (#395)
- Fix incorrect plural in summary message (#386)
### Enhancements
- Baseline now stores the source code for better matching (#415)
- Duplicates are no longer stored in the baseline (#231)

## [1.6.0]
### Added
- Support using `TypeVar`s in the bounds of other `TypeVar`s
### Enhancements
- Similar errors on the same line will now not be removed
- Render generic upper bound with `: ` instead of ` <: `
- Render uninhabited type as `Never` instead of `<nothing>`
- Render Callables with `-> None`
### Fixes
- Handle positional only `/` parameters in overload implementation inference
- Render inferred literal without `?`
- Fix infer from defaults for inner functions

## [1.5.0]
### Added
- Allow literal `int`, `bool` and `Enum`s without `Literal`
### Enhancements
- Unionize at type joins instead of common ancestor
- Render Literal types better in output messages

## [1.4.0]
### Added
- `ignore_any_from_errors` option to suppress `no-any-expr` messages from other errors
- Function types are inferred from Overloads, overrides and default values. (no overrides for now sorry)
- Infer Property types
- Calls to incomplete functions are an error (configurable with `incomplete_is_typed`)
- Added a new type `Untyped`, it's like `Any`, but more specific
- Added a dependency on `basedtyping`
### Enhancements
- Render types a lot better in output messages
### Fixes
- `types.NoneType` now works as a value of `type[None]`

## [1.3.0]
### Added
- `default_return` option to imply unannotated return type as `None`.
- Specific error codes for `Any` errors
- Automatic baseline mode, if there are no new errors then write.
- Ignore baseline with `mypy --baseline-file= src`
### Enhancements
- Baseline will ignore reveals (`reveal_type` and `reveal_locals`).
- `--write-baseline` will report total and new errors.
- Much better baseline matching.

## [1.2.0]
### Added
- Unions in output messages show with new syntax
- `--legacy` flag
- new baseline format

## [1.0.0]
### Added
- Strict by default(`--strict` and disable dynamic typing)
- add baseline support(`--write-baseline`, `--baseline-file`)
- Type ignore must specify error code
- Unused type ignore can be ignored
- Add error code for unsafe variance(`unsafe-variance`)
