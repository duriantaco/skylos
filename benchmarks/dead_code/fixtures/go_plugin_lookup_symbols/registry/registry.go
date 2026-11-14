package registry

type Table struct{ entries map[string]string }

func (t Table) Lookup(name string) string { return t.entries[name] }

func Default(t Table) string { return t.Lookup("Orphan") }
