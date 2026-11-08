package differentName
type Box[T any] struct{}
func (Box[T]) Invoke(callback func()) { callback() }
