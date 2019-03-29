package finalizers

type Finalizer interface {
	GetFinalizers() []string
}

func AddFinalizer(obj Finalizer, finalizer string) []string {
	finalizers := obj.GetFinalizers()
	for _, f := range finalizers {
		if finalizer == f {
			return finalizers
		}
	}
	return append([]string{finalizer}, finalizers...)
}

func HasFinalizer(obj Finalizer, finalizer string) bool {
	finalizers := obj.GetFinalizers()
	for _, f := range finalizers {
		if finalizer == f {
			return true
		}
	}
	return false
}

func RemoveFinalizer(obj Finalizer, finalizer string) []string {
	finalizers := []string{}
	for _, f := range obj.GetFinalizers() {
		if f == finalizer {
			continue
		}
		finalizers = append(finalizers, f)
	}
	return finalizers
}
