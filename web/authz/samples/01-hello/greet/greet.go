package greet

// Greet builds a greeting; calls Msg (an in-module call edge).
func Greet() string { return "hi " + Msg() }

// Msg is the message.
func Msg() string { return "world" }
