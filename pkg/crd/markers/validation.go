/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package markers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"strings"

	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	"sigs.k8s.io/controller-tools/pkg/markers"
)

const (
	SchemalessName = "kubebuilder:validation:Schemaless"
)

// ValidationMarkers lists all available markers that affect CRD schema generation,
// except for the few that don't make sense as type-level markers (see FieldOnlyMarkers).
// All markers start with `+kubebuilder:validation:`, and continue with their type name.
// A copy is produced of all markers that describes types as well, for making types
// reusable and writing complex validations on slice items.
var ValidationMarkers = mustMakeAllWithPrefix("kubebuilder:validation", markers.DescribesField,

	// numeric markers

	Maximum(0),
	Minimum(0),
	ExclusiveMaximum(false),
	ExclusiveMinimum(false),
	MultipleOf(0),
	MinProperties(0),
	MaxProperties(0),

	// string markers

	MaxLength(0),
	MinLength(0),
	Pattern(""),

	// slice markers

	MaxItems(0),
	MinItems(0),
	UniqueItems(false),

	// general markers

	Enum(nil),
	Format(""),
	Type(""),
	OneOf(""),
	XPreserveUnknownFields{},
	XEmbeddedResource{},
	XIntOrString{},
	XValidation{},
)

// FieldOnlyMarkers list field-specific validation markers (i.e. those markers that don't make
// sense on a type, and thus aren't in ValidationMarkers).
var FieldOnlyMarkers = []*definitionWithHelp{
	must(markers.MakeDefinition("kubebuilder:validation:Required", markers.DescribesField, struct{}{})).
		WithHelp(markers.SimpleHelp("CRD validation", "specifies that this field is required, if fields are optional by default.")),
	must(markers.MakeDefinition("kubebuilder:validation:Optional", markers.DescribesField, struct{}{})).
		WithHelp(markers.SimpleHelp("CRD validation", "specifies that this field is optional, if fields are required by default.")),
	must(markers.MakeDefinition("optional", markers.DescribesField, struct{}{})).
		WithHelp(markers.SimpleHelp("CRD validation", "specifies that this field is optional, if fields are required by default.")),

	must(markers.MakeDefinition("nullable", markers.DescribesField, Nullable{})).
		WithHelp(Nullable{}.Help()),

	must(markers.MakeAnyTypeDefinition("kubebuilder:default", markers.DescribesField, Default{})).
		WithHelp(Default{}.Help()),

	must(markers.MakeAnyTypeDefinition("kubebuilder:example", markers.DescribesField, Example{})).
		WithHelp(Example{}.Help()),

	must(markers.MakeDefinition("kubebuilder:validation:EmbeddedResource", markers.DescribesField, XEmbeddedResource{})).
		WithHelp(XEmbeddedResource{}.Help()),

	must(markers.MakeDefinition(SchemalessName, markers.DescribesField, Schemaless{})).
		WithHelp(Schemaless{}.Help()),

	must(markers.MakeAnyTypeDefinition("deckhouse:xdoc:default", markers.DescribesField, DeckhouseDocDefault{})).
		WithHelp(DeckhouseDocDefault{}.Help()),

	must(markers.MakeAnyTypeDefinition("deckhouse:xdoc:example", markers.DescribesField, DeckhouseDocExample{})).
		WithHelp(DeckhouseDocExample{}.Help()),
}

// ValidationIshMarkers are field-and-type markers that don't fall under the
// :validation: prefix, and/or don't have a name that directly matches their
// type.
var ValidationIshMarkers = []*definitionWithHelp{
	must(markers.MakeDefinition("kubebuilder:pruning:PreserveUnknownFields", markers.DescribesField, XPreserveUnknownFields{})).
		WithHelp(XPreserveUnknownFields{}.Help()),
	must(markers.MakeDefinition("kubebuilder:pruning:PreserveUnknownFields", markers.DescribesType, XPreserveUnknownFields{})).
		WithHelp(XPreserveUnknownFields{}.Help()),
}

func init() {
	AllDefinitions = append(AllDefinitions, ValidationMarkers...)

	for _, def := range ValidationMarkers {
		newDef := *def.Definition
		// copy both parts so we don't change the definition
		typDef := definitionWithHelp{
			Definition: &newDef,
			Help:       def.Help,
		}
		typDef.Target = markers.DescribesType
		AllDefinitions = append(AllDefinitions, &typDef)
	}

	AllDefinitions = append(AllDefinitions, FieldOnlyMarkers...)
	AllDefinitions = append(AllDefinitions, ValidationIshMarkers...)
}

// +controllertools:marker:generateHelp:category="CRD validation"
// Maximum specifies the maximum numeric value that this field can have.
type Maximum float64

func (m Maximum) Value() float64 {
	return float64(m)
}

// +controllertools:marker:generateHelp:category="CRD validation"
// Minimum specifies the minimum numeric value that this field can have. Negative numbers are supported.
type Minimum float64

func (m Minimum) Value() float64 {
	return float64(m)
}

// +controllertools:marker:generateHelp:category="CRD validation"
// ExclusiveMinimum indicates that the minimum is "up to" but not including that value.
type ExclusiveMinimum bool

// +controllertools:marker:generateHelp:category="CRD validation"
// ExclusiveMaximum indicates that the maximum is "up to" but not including that value.
type ExclusiveMaximum bool

// +controllertools:marker:generateHelp:category="CRD validation"
// MultipleOf specifies that this field must have a numeric value that's a multiple of this one.
type MultipleOf float64

func (m MultipleOf) Value() float64 {
	return float64(m)
}

// +controllertools:marker:generateHelp:category="CRD validation"
// MaxLength specifies the maximum length for this string.
type MaxLength int

// +controllertools:marker:generateHelp:category="CRD validation"
// MinLength specifies the minimum length for this string.
type MinLength int

// +controllertools:marker:generateHelp:category="CRD validation"
// Pattern specifies that this string must match the given regular expression.
type Pattern string

// +controllertools:marker:generateHelp:category="CRD validation"
// MaxItems specifies the maximum length for this list.
type MaxItems int

// +controllertools:marker:generateHelp:category="CRD validation"
// MinItems specifies the minimum length for this list.
type MinItems int

// +controllertools:marker:generateHelp:category="CRD validation"
// UniqueItems specifies that all items in this list must be unique.
type UniqueItems bool

// +controllertools:marker:generateHelp:category="CRD validation"
// MaxProperties restricts the number of keys in an object
type MaxProperties int

// +controllertools:marker:generateHelp:category="CRD validation"
// MinProperties restricts the number of keys in an object
type MinProperties int

// +controllertools:marker:generateHelp:category="CRD validation"
// Enum specifies that this (scalar) field is restricted to the *exact* values specified here.
type Enum []interface{}

// +controllertools:marker:generateHelp:category="CRD validation"
// Format specifies additional "complex" formatting for this field.
//
// For example, a date-time field would be marked as "type: string" and
// "format: date-time".
type Format string

// +controllertools:marker:generateHelp:category="CRD validation"
// Type overrides the type for this field (which defaults to the equivalent of the Go type).
//
// This generally must be paired with custom serialization.  For example, the
// metav1.Time field would be marked as "type: string" and "format: date-time".
type Type string

// +controllertools:marker:generateHelp:category="CRD validation"
// Nullable marks this field as allowing the "null" value.
//
// This is often not necessary, but may be helpful with custom serialization.
type Nullable struct{}

// +controllertools:marker:generateHelp:category="CRD validation"
// Default sets the default value for this field.
//
// A default value will be accepted as any value valid for the
// field. Formatting for common types include: boolean: `true`, string:
// `Cluster`, numerical: `1.24`, array: `{1,2}`, object: `{policy:
// "delete"}`). Defaults should be defined in pruned form, and only best-effort
// validation will be performed. Full validation of a default requires
// submission of the containing CRD to an apiserver.
type Default struct {
	Value interface{}
}

// +controllertools:marker:generateHelp:category="CRD validation"
// Example sets the example value for this field.
//
// An example value will be accepted as any value valid for the
// field. Formatting for common types include: boolean: `true`, string:
// `Cluster`, numerical: `1.24`, array: `{1,2}`, object: `{policy:
// "delete"}`). Examples should be defined in pruned form, and only best-effort
// validation will be performed. Full validation of an example requires
// submission of the containing CRD to an apiserver.
type Example struct {
	Value interface{}
}

// +controllertools:marker:generateHelp:category="CRD processing"
// PreserveUnknownFields stops the apiserver from pruning fields which are not specified.
//
// By default the apiserver drops unknown fields from the request payload
// during the decoding step. This marker stops the API server from doing so.
// It affects fields recursively, but switches back to normal pruning behaviour
// if nested  properties or additionalProperties are specified in the schema.
// This can either be true or undefined. False
// is forbidden.
//
// NB: The kubebuilder:validation:XPreserveUnknownFields variant is deprecated
// in favor of the kubebuilder:pruning:PreserveUnknownFields variant.  They function
// identically.
type XPreserveUnknownFields struct{}

// +controllertools:marker:generateHelp:category="CRD validation"
// EmbeddedResource marks a fields as an embedded resource with apiVersion, kind and metadata fields.
//
// An embedded resource is a value that has apiVersion, kind and metadata fields.
// They are validated implicitly according to the semantics of the currently
// running apiserver. It is not necessary to add any additional schema for these
// field, yet it is possible. This can be combined with PreserveUnknownFields.
type XEmbeddedResource struct{}

// +controllertools:marker:generateHelp:category="CRD validation"
// IntOrString marks a fields as an IntOrString.
//
// This is required when applying patterns or other validations to an IntOrString
// field. Knwon information about the type is applied during the collapse phase
// and as such is not normally available during marker application.
type XIntOrString struct{}

// +controllertools:marker:generateHelp:category="CRD validation"
// Schemaless marks a field as being a schemaless object.
//
// Schemaless objects are not introspected, so you must provide
// any type and validation information yourself. One use for this
// tag is for embedding fields that hold JSONSchema typed objects.
// Because this field disables all type checking, it is recommended
// to be used only as a last resort.
type Schemaless struct{}

func hasNumericType(schema *apiext.JSONSchemaProps) bool {
	return schema.Type == "integer" || schema.Type == "number"
}

func isIntegral(value float64) bool {
	return value == math.Trunc(value) && !math.IsNaN(value) && !math.IsInf(value, 0)
}

// +controllertools:marker:generateHelp:category="CRD validation"
// XValidation marks a field as requiring a value for which a given
// expression evaluates to true.
//
// This marker may be repeated to specify multiple expressions, all of
// which must evaluate to true.
type XValidation struct {
	Rule    string
	Message string `marker:",optional"`
}

func (m Maximum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if !hasNumericType(schema) {
		return fmt.Errorf("must apply maximum to a numeric value, found %s", schema.Type)
	}

	if schema.Type == "integer" && !isIntegral(m.Value()) {
		return fmt.Errorf("cannot apply non-integral maximum validation (%v) to integer value", m.Value())
	}

	val := m.Value()
	schema.Maximum = &val
	return nil
}

func (m Minimum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if !hasNumericType(schema) {
		return fmt.Errorf("must apply minimum to a numeric value, found %s", schema.Type)
	}

	if schema.Type == "integer" && !isIntegral(m.Value()) {
		return fmt.Errorf("cannot apply non-integral minimum validation (%v) to integer value", m.Value())
	}

	val := m.Value()
	schema.Minimum = &val
	return nil
}

func (m ExclusiveMaximum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if !hasNumericType(schema) {
		return fmt.Errorf("must apply exclusivemaximum to a numeric value, found %s", schema.Type)
	}
	schema.ExclusiveMaximum = bool(m)
	return nil
}

func (m ExclusiveMinimum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if !hasNumericType(schema) {
		return fmt.Errorf("must apply exclusiveminimum to a numeric value, found %s", schema.Type)
	}

	schema.ExclusiveMinimum = bool(m)
	return nil
}

func (m MultipleOf) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if !hasNumericType(schema) {
		return fmt.Errorf("must apply multipleof to a numeric value, found %s", schema.Type)
	}

	if schema.Type == "integer" && !isIntegral(m.Value()) {
		return fmt.Errorf("cannot apply non-integral multipleof validation (%v) to integer value", m.Value())
	}

	val := m.Value()
	schema.MultipleOf = &val
	return nil
}

func (m MaxLength) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "string" {
		return fmt.Errorf("must apply maxlength to a string")
	}
	val := int64(m)
	schema.MaxLength = &val
	return nil
}

func (m MinLength) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "string" {
		return fmt.Errorf("must apply minlength to a string")
	}
	val := int64(m)
	schema.MinLength = &val
	return nil
}

func (m Pattern) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	// Allow string types or IntOrStrings. An IntOrString will still
	// apply the pattern validation when a string is detected, the pattern
	// will not apply to ints though.
	if schema.Type != "string" && !schema.XIntOrString {
		return fmt.Errorf("must apply pattern to a `string` or `IntOrString`")
	}
	schema.Pattern = string(m)
	return nil
}

func (m MaxItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply maxitem to an array")
	}
	val := int64(m)
	schema.MaxItems = &val
	return nil
}

func (m MinItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply minitems to an array")
	}
	val := int64(m)
	schema.MinItems = &val
	return nil
}

func (m UniqueItems) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "array" {
		return fmt.Errorf("must apply uniqueitems to an array")
	}
	schema.UniqueItems = bool(m)
	return nil
}

func (m MinProperties) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "object" {
		return fmt.Errorf("must apply minproperties to an object")
	}
	val := int64(m)
	schema.MinProperties = &val
	return nil
}

func (m MaxProperties) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	if schema.Type != "object" {
		return fmt.Errorf("must apply maxproperties to an object")
	}
	val := int64(m)
	schema.MaxProperties = &val
	return nil
}

func (m Enum) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	// TODO(directxman12): this is a bit hacky -- we should
	// probably support AnyType better + using the schema structure
	vals := make([]apiext.JSON, len(m))
	for i, val := range m {
		// TODO(directxman12): check actual type with schema type?
		// if we're expecting a string, marshal the string properly...
		// NB(directxman12): we use json.Marshal to ensure we handle JSON escaping properly
		valMarshalled, err := json.Marshal(val)
		if err != nil {
			return err
		}
		vals[i] = apiext.JSON{Raw: valMarshalled}
	}
	schema.Enum = vals
	return nil
}

func (m Format) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.Format = string(m)
	return nil
}

// NB(directxman12): we "typecheck" on target schema properties here,
// which means the "Type" marker *must* be applied first.
// TODO(directxman12): find a less hacky way to do this
// (we could preserve ordering of markers, but that feels bad in its own right).

func (m Type) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.Type = string(m)
	return nil
}

func (m Type) ApplyFirst() {}

func (m Nullable) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.Nullable = true
	return nil
}

// Defaults are only valid CRDs created with the v1 API
func (m Default) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	marshalledDefault, err := json.Marshal(m.Value)
	if err != nil {
		return err
	}
	schema.Default = &apiext.JSON{Raw: marshalledDefault}
	return nil
}

func (m Example) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	marshalledExample, err := json.Marshal(m.Value)
	if err != nil {
		return err
	}
	schema.Example = &apiext.JSON{Raw: marshalledExample}
	return nil
}

func (m XPreserveUnknownFields) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	defTrue := true
	schema.XPreserveUnknownFields = &defTrue
	return nil
}

func (m XEmbeddedResource) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.XEmbeddedResource = true
	return nil
}

// NB(JoelSpeed): we use this property in other markers here,
// which means the "XIntOrString" marker *must* be applied first.

func (m XIntOrString) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.XIntOrString = true
	return nil
}

func (m XIntOrString) ApplyFirst() {}

func (m XValidation) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	schema.XValidations = append(schema.XValidations, apiext.ValidationRule{
		Rule:    m.Rule,
		Message: m.Message,
	})
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// DeckhouseDocDefault configures the additional x-doc-default field
// for property with default value for deckhouse documentation.
type DeckhouseDocDefault struct {
	Value interface{}
}

func (m DeckhouseDocDefault) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	marshalledDocDefault, err := json.Marshal(m.Value)
	if err != nil {
		return err
	}
	schema.XDocDefault = &apiext.JSON{Raw: marshalledDocDefault}
	return nil
}

// +controllertools:marker:generateHelp:category=CRD

// DeckhouseDocDefault configures the additional x-doc-example field
// for property with example usage for deckhouse documentation.
type DeckhouseDocExample struct {
	Value interface{}
}

func (m DeckhouseDocExample) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	marshalledDocExample, err := json.Marshal(m.Value)
	if err != nil {
		return err
	}
	if schema.XDocExample != nil && len(schema.XDocExample.Raw) > 0 {
		fullString := bytes.Join([][]byte{
			escapeString(schema.XDocExample.Raw),
			escapeString(marshalledDocExample),
		}, []byte("\n"))
		marshalFullString, err := json.Marshal(string(fullString))
		if err != nil {
			return err
		}
		marshalledDocExample = marshalFullString
	}
	schema.XDocExample = &apiext.JSON{Raw: marshalledDocExample}

	return nil
}

func escapeString(b []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\""), nil), []byte("\\n"), []byte("\n"))
}

// +controllertools:marker:generateHelp:category=CRD

// OneOf configures file name and variable name at package level
// that will be used to generate oneOf CRD field.
// for Example, for comment deckhouse:one:of=./cronjob_types.go=OneOfCRD
// generator will search in package root for file ./cronjob_types.go and declared variable "OneOfCRD" in it
//
// file: ./cronjob_types.go:
//
//	package api
//
//	import (
//		metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//	)
//
//	const OneOfCRD = `
//	- required: [layout]
//	  properties:
//		layout:
//		  enum: [Standard]
//	- required: [layout]
//	  properties:
//		layout:
//		  enum: [WithoutNAT]
//	  masterNodeGroup:
//		properties:
//		  instanceClass:
//			type: object
//			properties:
//			  disableExternalIP:
//				enum: [false]
//
// `
//
// const "OneOfCRD" would be parsed to oneOf field of CRD as it is
type OneOf string

func (m OneOf) ApplyToSchema(schema *apiext.JSONSchemaProps) error {
	jsonProps, err := parseJSONSchemaPropsFromMarkerValue(string(m))
	if err != nil {
		return err
	}
	schema.OneOf = append(schema.OneOf, jsonProps...)
	return nil
}

func parseJSONSchemaPropsFromMarkerValue(m string) ([]apiext.JSONSchemaProps, error) {
	fileName, varName, err := fileNameVarNameFromMarkerValue(m)
	if err != nil {
		return nil, err
	}

	constant, err := constFromFileNameVarName(fileName, varName)
	if err != nil {
		return nil, err
	}

	jsonProps, err := parseJSONSchemaPropsFromAstVariable(constant)
	if err != nil {
		return nil, err
	}
	return jsonProps, nil
}

func fileNameVarNameFromMarkerValue(m string) (string, string, error) {
	fc := strings.SplitN(string(m), "=", 2)
	if len(fc) < 2 {
		return "", "", fmt.Errorf("deckhouse:one:of not in format '<file name>=<variable name>'")
	}
	return fc[0], fc[1], nil
}

func constFromFileNameVarName(fileName, varName string) (*ast.ValueSpec, error) {
	file, err := parser.ParseFile(token.NewFileSet(), fileName, nil, 0)
	if err != nil {
		return nil, err
	}
	astVar, ok := file.Scope.Objects[varName]
	if !ok {
		return nil, fmt.Errorf("no variable found with name '%s' in file '%s'", varName, fileName)
	}

	if astVar.Kind.String() != "const" {
		return nil, fmt.Errorf("variable '%s' from file '%s' should be 'const'", varName, fileName)
	}

	variable, ok := astVar.Decl.(*ast.ValueSpec)
	if !ok {
		return nil, fmt.Errorf("bad const format, should be 'const <var name> = ...' at package level")
	}
	return variable, nil
}

func parseJSONSchemaPropsFromAstVariable(variable *ast.ValueSpec) ([]apiext.JSONSchemaProps, error) {
	value, ok := variable.Values[0].(*ast.BasicLit)
	if !ok {
		return nil, fmt.Errorf("bad variable format, should be 'var/const <var name> = <string value>' at package level")
	}

	if value.Kind.String() != "STRING" {
		return nil, fmt.Errorf("variable should be of type `string`")
	}

	stringValue := strings.Trim(value.Value, "`\"'")
	var props []apiext.JSONSchemaProps
	if err := yaml.Unmarshal([]byte(stringValue), &props); err != nil {
		return nil, err
	}
	return props, nil
}
