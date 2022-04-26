package udp

import "strings"

type setDontFragmentError struct {
	Err4, Err6 error
}

func (e *setDontFragmentError) Error() string {
	var ss []string
	if e.Err4 != nil {
		ss = append(ss, "IPv4: "+e.Err4.Error())
	}
	if e.Err6 != nil {
		ss = append(ss, "IPv6: "+e.Err6.Error())
	}
	return "set Don't Fragment: " + strings.Join(ss, ", ")
}
