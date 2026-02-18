module github.com/corvusHold/guard/examples/oauth2-bff-go/backend

go 1.24.6

require github.com/corvusHold/guard/sdk/go v0.0.0

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.4.0 // indirect
	github.com/oapi-codegen/runtime v1.1.0 // indirect
)

replace github.com/corvusHold/guard/sdk/go => ../../../sdk/go
