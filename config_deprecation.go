// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
)

// migrationGuideURL is the published location of docs/migration.md. Every
// deprecation warning links to a heading in that guide, which is what the
// Collector's component-stability rules ask of a beta component: a renamed
// or removed option logs a WARN "with a link to a place within the
// component's repository where the change is documented and a migration path
// is provided".
const migrationGuideURL = "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/migration.md"

// minimumReleasesBeforeRemoval is the N+2 part of the policy: a key retired
// in release N stays accepted in N+1 and may be dropped no earlier than N+2. The six-month floor that accompanies it is a calendar rule that
// the release checklist enforces; the version arithmetic here cannot see it.
const minimumReleasesBeforeRemoval = 2

var (
	// configKeyPattern is a dotted path of mapstructure keys relative to the
	// exporter block, e.g. "write.stream_pool_size".
	configKeyPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
	// releasePattern is a tagged release of this repository or, once the
	// component lives in contrib, of the contrib release train.
	releasePattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
	// anchorPattern is a GitHub heading anchor as it appears after '#'.
	anchorPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// deprecatedConfigKey retires one configuration key. The registry below is
// the single place a rename or removal is declared; config_inventory_test.go
// refuses a key that disappears from Config without an entry here, and
// docs/migration.md must carry the heading that Anchor points at.
type deprecatedConfigKey struct {
	// OldPath is the dotted key being retired, relative to the exporter
	// block, for example "write.stream_pool_size".
	OldPath string
	// NewPath is the replacement key in the same notation. Empty when the
	// key is removed without a replacement; its value is then dropped.
	NewPath string
	// DeprecatedIn is the first release that warns about OldPath (release N).
	DeprecatedIn string
	// RemovalEarliest is the earliest release that may stop accepting
	// OldPath. It must be at least N+2; the policy also requires six months.
	RemovalEarliest string
	// Anchor is the heading anchor in docs/migration.md that documents the
	// change and the migration path.
	Anchor string
}

// deprecatedConfigKeys is the registry of retired configuration keys. It is
// empty until a rename or removal ships; the mechanism, its tests and the
// inventory gate are in place so that the first such change is a one-line
// addition here plus a section in docs/migration.md.
var deprecatedConfigKeys []deprecatedConfigKey

// migrationLink is the URL a warning carries for this rule.
func (r deprecatedConfigKey) migrationLink() string {
	return migrationGuideURL + "#" + r.Anchor
}

// configDeprecations records the rules Unmarshal applied to a configuration
// so the first exporter built from it warns exactly once per key, however
// many signal pipelines share the block.
type configDeprecations struct {
	once    sync.Once
	applied []deprecatedConfigKey
}

// plainConfig is Config without its confmap.Unmarshaler method, so
// work.Unmarshal((*plainConfig)(cfg)) decodes the rewritten map onto cfg
// without re-entering Config.Unmarshal when a caller invokes
// cfg.Unmarshal(conf) directly.
type plainConfig Config

// Unmarshal implements confmap.Unmarshaler. It rewrites deprecated keys to
// their replacements before the regular decode so that an old key neither
// fails the unknown-key check nor silently loses its value.
func (cfg *Config) Unmarshal(conf *confmap.Conf) error {
	return cfg.unmarshalWithDeprecations(conf, deprecatedConfigKeys)
}

func (cfg *Config) unmarshalWithDeprecations(conf *confmap.Conf, rules []deprecatedConfigKey) error {
	cfg.deprecations = nil
	if err := validateDeprecationRules(rules); err != nil {
		return err
	}
	if conf == nil {
		return nil
	}
	work, applied, err := applyConfigDeprecations(conf, rules)
	if err != nil {
		return err
	}
	if err := work.Unmarshal((*plainConfig)(cfg)); err != nil {
		return err
	}
	if len(applied) == 0 {
		return nil
	}
	src, err := conf.Sub("")
	if err != nil {
		return err
	}
	root := reflect.ValueOf(cfg).Elem()
	var errs []error
	for _, rule := range applied {
		if rule.NewPath == "" {
			continue
		}
		if err := decodeDeprecatedValue(root, src, rule); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	cfg.deprecations = &configDeprecations{applied: applied}
	return nil
}

// applyConfigDeprecations clones conf, checks for conflicts between
// deprecated keys and their replacements, deletes matched OldPath entries
// from the clone so strict unknown-key decoding succeeds, and returns the
// cloned Conf alongside the rules that matched in registry order. The
// caller's conf is never modified.
//
// For each rule whose OldPath is set:
//   - when NewPath is empty, OldPath is deleted and its value dropped;
//   - when NewPath is also set (or claimed by an earlier rule), the
//     configuration is rejected: two values for one setting are ambiguous,
//     and failing at startup is cheaper than guessing which one the operator
//     meant;
//   - otherwise OldPath is deleted from the returned work Conf and recorded
//     in applied so unmarshalWithDeprecations can decode its raw value
//     (preserving confmap ExpandedValue metadata from ${env:...} expansions)
//     into NewPath on Config.
//
// A rule whose OldPath is not set is a no-op. Invalid rules fail before any
// key is touched.
func applyConfigDeprecations(conf *confmap.Conf, rules []deprecatedConfigKey) (*confmap.Conf, []deprecatedConfigKey, error) {
	if err := validateDeprecationRules(rules); err != nil {
		return nil, nil, err
	}
	if conf == nil {
		return confmap.New(), nil, nil
	}
	work, err := conf.Sub("")
	if err != nil {
		return nil, nil, err
	}
	var (
		applied []deprecatedConfigKey
		errs    []error
	)
	claimedNew := make(map[string]string, len(rules))
	for _, rule := range rules {
		oldKey := confmapKey(rule.OldPath)
		if !work.IsSet(oldKey) {
			continue
		}
		if rule.NewPath != "" {
			newKey := confmapKey(rule.NewPath)
			if work.IsSet(newKey) {
				errs = append(errs, fmt.Errorf(
					"%s is deprecated and replaced by %s, but both are set; remove %s (see %s)",
					rule.OldPath, rule.NewPath, rule.OldPath, rule.migrationLink()))
				continue
			}
			if prevOld, dup := claimedNew[rule.NewPath]; dup {
				errs = append(errs, fmt.Errorf(
					"%s and %s both map to %s, and both are set; remove %s (see %s)",
					prevOld, rule.OldPath, rule.NewPath, rule.OldPath, rule.migrationLink()))
				continue
			}
			claimedNew[rule.NewPath] = rule.OldPath
		}
		work.Delete(oldKey)
		applied = append(applied, rule)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, nil, err
	}
	return work, applied, nil
}

// decodeDeprecatedValue decodes the value at rule.OldPath in src directly
// into the field at rule.NewPath on root (a Config struct value) using
// confmap.Conf.Unmarshal so that confmap's internal ExpandedValue wrapper
// (used for ${env:...} string/opaque expansions) and decode hooks are
// preserved.
func decodeDeprecatedValue(root reflect.Value, src *confmap.Conf, rule deprecatedConfigKey) error {
	dstField, err := lookupConfigField(root, rule.NewPath)
	if err != nil {
		return fmt.Errorf("moving %s to %s: %w", rule.OldPath, rule.NewPath, err)
	}
	if dstField.Kind() == reflect.Struct && dstField.Type().PkgPath() == reflect.TypeFor[Config]().PkgPath() {
		sub, err := src.Sub(confmapKey(rule.OldPath))
		if err != nil {
			return fmt.Errorf("moving %s to %s: %w", rule.OldPath, rule.NewPath, err)
		}
		dstCopy := reflect.New(dstField.Type())
		dstCopy.Elem().Set(dstField)
		if err := sub.Unmarshal(dstCopy.Interface()); err != nil {
			return fmt.Errorf("moving %s to %s: %w", rule.OldPath, rule.NewPath, err)
		}
		dstField.Set(dstCopy.Elem())
		return nil
	}

	parts := strings.Split(rule.OldPath, ".")
	curType := dstField.Type()
	for i := len(parts) - 1; i >= 0; i-- {
		curType = reflect.StructOf([]reflect.StructField{{
			Name: "V",
			Type: curType,
			Tag:  reflect.StructTag(fmt.Sprintf(`mapstructure:%q`, parts[i])),
		}})
	}
	holder := reflect.New(curType)
	leaf := holder.Elem()
	for range parts {
		leaf = leaf.Field(0)
	}
	leaf.Set(dstField)
	if err := src.Unmarshal(holder.Interface(), confmap.WithIgnoreUnused()); err != nil {
		return fmt.Errorf("moving %s to %s: %w", rule.OldPath, rule.NewPath, err)
	}
	dstField.Set(leaf)
	return nil
}

func lookupConfigField(v reflect.Value, path string) (reflect.Value, error) {
	cur := v
	for part := range strings.SplitSeq(path, ".") {
		next, ok := findStructFieldByMapstructureName(cur, part)
		if !ok {
			return reflect.Value{}, fmt.Errorf("unknown destination key %q", path)
		}
		cur = next
	}
	return cur, nil
}

func findStructFieldByMapstructureName(v reflect.Value, name string) (reflect.Value, bool) {
	if v.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}
	st := v.Type()
	for i := range st.NumField() {
		f := st.Field(i)
		if !f.IsExported() {
			continue
		}
		tag, ok := f.Tag.Lookup("mapstructure")
		if !ok {
			continue
		}
		tagName, opts, _ := strings.Cut(tag, ",")
		if tagName == "-" {
			continue
		}
		fv := v.Field(i)
		if slices.Contains(strings.Split(opts, ","), "squash") && fv.Kind() == reflect.Struct {
			if found, ok := findStructFieldByMapstructureName(fv, name); ok {
				return found, true
			}
			continue
		}
		if tagName == name {
			return fv, true
		}
	}
	return reflect.Value{}, false
}

// logConfigDeprecations emits one WARN per deprecated key that Unmarshal
// rewrote, the first time it is called for a configuration. Later calls, for
// example from the logs and metrics exporters sharing the block with the
// traces exporter, log nothing.
func logConfigDeprecations(logger *zap.Logger, cfg *Config) {
	if logger == nil || cfg == nil || cfg.deprecations == nil {
		return
	}
	cfg.deprecations.once.Do(func() {
		for _, rule := range cfg.deprecations.applied {
			fields := []zap.Field{
				zap.String("deprecated_key", rule.OldPath),
				zap.String("deprecated_in", rule.DeprecatedIn),
				zap.String("removal_earliest", rule.RemovalEarliest),
				zap.String("migration_guide", rule.migrationLink()),
			}
			if rule.NewPath == "" {
				logger.Warn(fmt.Sprintf(
					"configuration key %q is deprecated and has no effect; remove it (deprecated in %s, removal no earlier than %s): %s",
					rule.OldPath, rule.DeprecatedIn, rule.RemovalEarliest, rule.migrationLink()), fields...)
				continue
			}
			logger.Warn(fmt.Sprintf(
				"configuration key %q is deprecated; its value was applied to %q (deprecated in %s, removal no earlier than %s): %s",
				rule.OldPath, rule.NewPath, rule.DeprecatedIn, rule.RemovalEarliest, rule.migrationLink()),
				append(fields, zap.String("replacement_key", rule.NewPath))...)
		}
	})
}

// validateDeprecationRules checks the registry itself: well-formed paths,
// distinct old keys, parseable releases, a removal release at least
// minimumReleasesBeforeRemoval after the deprecation release, and an anchor
// that can follow '#'. Whether the anchor exists in docs/migration.md is
// checked by config_inventory_test.go, which can read the file.
func validateDeprecationRules(rules []deprecatedConfigKey) error {
	var errs []error
	seen := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		at := fmt.Sprintf("deprecation rule %d (%q)", i, r.OldPath)
		if !configKeyPattern.MatchString(r.OldPath) {
			errs = append(errs, fmt.Errorf("%s: OldPath must be a dotted key like write.stream_pool_size", at))
		}
		if _, dup := seen[r.OldPath]; dup {
			errs = append(errs, fmt.Errorf("%s: OldPath is listed twice", at))
		}
		seen[r.OldPath] = struct{}{}
		if r.NewPath != "" && !configKeyPattern.MatchString(r.NewPath) {
			errs = append(errs, fmt.Errorf("%s: NewPath %q must be a dotted key or empty", at, r.NewPath))
		}
		if r.NewPath == r.OldPath {
			errs = append(errs, fmt.Errorf("%s: NewPath must differ from OldPath", at))
		}
		if !anchorPattern.MatchString(r.Anchor) {
			errs = append(errs, fmt.Errorf("%s: Anchor %q must be a lowercase heading anchor", at, r.Anchor))
		}
		distance, err := releaseDistance(r.DeprecatedIn, r.RemovalEarliest)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", at, err))
		case distance < minimumReleasesBeforeRemoval:
			errs = append(errs, fmt.Errorf("%s: RemovalEarliest %s is %d release(s) after DeprecatedIn %s; at least %d required",
				at, r.RemovalEarliest, distance, r.DeprecatedIn, minimumReleasesBeforeRemoval))
		}
	}
	return errors.Join(errs...)
}

// releaseDistance counts releases from one tag to a later one. Within a
// major version the distance is the difference in the component that moves
// (minor for the contrib train, patch for this repository's v0.0.N series). A
// major version bump counts as unbounded distance, because a new major is
// the one place breaking changes are expected anyway.
func releaseDistance(from, to string) (int, error) {
	a, err := parseRelease(from)
	if err != nil {
		return 0, fmt.Errorf("DeprecatedIn: %w", err)
	}
	b, err := parseRelease(to)
	if err != nil {
		return 0, fmt.Errorf("RemovalEarliest: %w", err)
	}
	switch {
	case b[0] > a[0]:
		return minimumReleasesBeforeRemoval, nil
	case b[0] < a[0]:
		return 0, fmt.Errorf("RemovalEarliest %s precedes DeprecatedIn %s", to, from)
	case b[1] != a[1]:
		if b[1] < a[1] {
			return 0, fmt.Errorf("RemovalEarliest %s precedes DeprecatedIn %s", to, from)
		}
		return b[1] - a[1], nil
	case b[2] < a[2]:
		return 0, fmt.Errorf("RemovalEarliest %s precedes DeprecatedIn %s", to, from)
	default:
		return b[2] - a[2], nil
	}
}

func parseRelease(s string) ([3]int, error) {
	var out [3]int
	m := releasePattern.FindStringSubmatch(s)
	if m == nil {
		return out, fmt.Errorf("release %q must look like v0.0.4", s)
	}
	for i := range 3 {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return out, fmt.Errorf("release %q: %w", s, err)
		}
		out[i] = n
	}
	return out, nil
}

// confmapKey converts a dotted configuration path to confmap's key notation.
func confmapKey(path string) string {
	return strings.ReplaceAll(path, ".", confmap.KeyDelimiter)
}
