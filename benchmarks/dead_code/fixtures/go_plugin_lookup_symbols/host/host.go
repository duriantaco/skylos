package host

import "plugin"

func Load(path string) (plugin.Symbol, error) {
	loaded, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := loaded.Lookup("Settings"); err != nil {
		return nil, err
	}
	if _, err := loaded.Lookup("describe"); err != nil {
		return nil, err
	}
	return loaded.Lookup("Describe")
}
