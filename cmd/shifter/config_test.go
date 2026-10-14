package main

import (
	"os"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// The rendered defaults parse back into the defaults, and the repository's
// config.yaml is that rendering.
func TestRenderRoundTrip(t *testing.T) {
	rendered := Render(Defaults())
	var f File
	if err := yaml.Unmarshal([]byte(rendered), &f); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f, Defaults()) {
		t.Errorf("the rendering does not parse back into the defaults:\n%+v\n%+v", f, Defaults())
	}
	if err := Defaults().Validate(); err == nil {
		t.Error("the defaults validate without an adapter")
	}
	d := Defaults()
	d.Sim = "default"
	if err := d.Validate(); err != nil {
		t.Errorf("the defaults under sim do not validate: %v", err)
	}
	repo, err := os.ReadFile("../../config.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	if string(repo) != rendered {
		t.Error("config.yaml.example in the repository is not Render(Defaults()); regenerate it by running the shifter in an empty directory and copying the config.yaml it writes")
	}
}

// A key left out takes its default; a wrong value is reported.
func TestLoad(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte("site:\n  adapter: Ethernet 3\n  timeout: 5s\nconsumer:\n  adapter: 10.0.0.1\ncontrol: limited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Site.Adapter != "Ethernet 3" || f.Site.Timeout.Seconds() != 5 || f.Site.Port != 47808 || f.Control != "limited" || len(f.Reserved.Services) != 10 {
		t.Errorf("loaded %+v", f)
	}
	if err := f.Validate(); err != nil {
		t.Error(err)
	}
	for name, text := range map[string]string{
		"bad level":    "sim: default\ncontrol: root\n",
		"bad property": "sim: default\npseudonym:\n  replaced: [no-such-thing]\n",
		"bad service":  "sim: default\nreserved:\n  services: [who-is]\n",
		"bad sim":      "sim: maybe\n",
		"no adapter":   "site:\n  adapter: x\n",
		"bad bbmd":     "sim: default\nsite:\n  bbmd: nowhere\n",
	} {
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := Load(path)
		if err == nil {
			err = f.Validate()
		}
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
