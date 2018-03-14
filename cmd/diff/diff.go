package main

import (
	"fmt"
	"reflect"
)

func Diff(a, b interface{}) bool {
	var _diff func(prefix string, a, b reflect.Value) bool
	_diff = func(prefix string, a, b reflect.Value) bool {
		if a.Type() != b.Type() {
			fmt.Printf("%s: (type) %v %v\n", prefix, a.Type().Name(), b.Type().Name())
			return false
		}
		switch a.Kind() {
		case reflect.Array, reflect.Slice:
			if a.Len() != b.Len() {
				fmt.Printf("%s: (len) %v %v\n", prefix, a.Len(), b.Len())
				return false
			}
			for i := 0; i < a.Len(); i++ {
				if !_diff(fmt.Sprintf("%s[%d]", prefix, i), a.Index(i), b.Index(i)) {
					return false
				}
			}
		case reflect.Map:
			if a.Len() != b.Len() {
				fmt.Printf("%s: (len) %v %v\n", prefix, a.Len(), b.Len())
				return false
			}
			for _, k := range a.MapKeys() {
				zero := reflect.Value{}
				if b.MapIndex(k) == zero {
					fmt.Printf("%s[%v]: %v <zero>\n", prefix, k.Interface(), a.MapIndex(k).Interface())
					return false
				}
				if !_diff(fmt.Sprintf("%s[%v]", prefix, k.Interface()), a.MapIndex(k), b.MapIndex(k)) {
					return false
				}
			}
			return true
		case reflect.Ptr:
			return _diff(prefix, a.Elem(), b.Elem())
		case reflect.Struct:
			rv := true
			for i := 0; i < a.NumField(); i++ {
				if a.Type().Field(i).PkgPath != "" { // not exported
					continue
				}
				if !_diff(fmt.Sprintf("%s.%s", prefix, a.Type().Field(i).Name), a.Field(i), b.Field(i)) {
					rv = false
				}
			}
			if !rv {
				return rv
			}
		default:
			if a.Interface() != b.Interface() {
				fmt.Printf("%s: %v / %v\n", prefix, a.Interface(), b.Interface())
				return false
			}
		}
		return true
	}
	return _diff("", reflect.ValueOf(a), reflect.ValueOf(b))
}
