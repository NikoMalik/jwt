package jwt

//datatracker.ietf.org/doc/html/rfc7519#section-6.1

const none Algorithm = -1

func None() Algorithm { return none }

func (Algorithm) NoneString() string { return "none" }
