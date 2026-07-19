// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package endpoint

const (
	endpointCreated string = "endpoint_created"
	endpointDeleted string = "endpoint_deleted"
)

type key struct {
	// index is the interface index (linux) / compartment id (windows). It is the
	// identifier the TCX/TC hook attaches with and is stable for the interface's
	// lifetime, unlike name and NetNsID which change as a pod's veth is renamed
	// and moved into its netns during init.
	index int
}

type cache map[key]interface{}

type EndpointEvent struct {
	// Type is the type of the event.
	Type EventType
	// Obj is the object that the event is about.
	Obj interface{}
}

func NewEndpointEvent(t EventType, obj interface{}) *EndpointEvent {
	return &EndpointEvent{
		Type: t,
		Obj:  obj,
	}
}

type EventType int

const (
	EndpointCreated EventType = iota
	EndpointDeleted
)

func (e EventType) String() string {
	switch e {
	case EndpointCreated:
		return endpointCreated
	case EndpointDeleted:
		return endpointDeleted
	default:
		return "unknown"
	}
}

func (c cache) deepcopy() cache {
	copy := make(cache)
	for k, v := range c {
		copy[k] = v
	}
	return copy
}
