#! /usr/bin/env bash
#
# Copyright 2023 Flant JSC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script is for generating new markers, new conversions and deepdopy funcs for CRDs (in vendor) and test data for new markers

set -xEeuo pipefail

go run ./cmd/helpgen/ generate:headerFile=./boilerplate.go.txt,year=2019 paths=./pkg/...

gen_flags="--input-dirs ./vendor/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/... --output-package ./vendor/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/ --go-header-file ./boilerplate.go.txt"
go run k8s.io/code-generator/cmd/conversion-gen@latest $gen_flags --output-file-base zz_generated.conversion
go run k8s.io/code-generator/cmd/deepcopy-gen@latest $gen_flags --output-file-base zz_generated.deepcopy

curr_dir=$(pwd)

cd pkg/crd/testdata && go generate && cd "$curr_dir"

CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -o /Users/alexmakh/golang/bin/controller-gen -mod=vendor ./cmd/controller-gen
