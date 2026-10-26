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
	if f.Survey.Enabled || f.Survey.At != "02:00" || f.Survey.Rate != 10 || len(f.Survey.Ranges) != 0 {
		t.Errorf("the survey defaults loaded as %+v", f.Survey)
	}
	if err := f.Validate(); err != nil {
		t.Error(err)
	}
	// A survey under sim is fine with ranges, and on an adapter without.
	if err := os.WriteFile(path, []byte("sim: default\nsurvey:\n  enabled: true\n  at: \"3:15\"\n  ranges: [127.0.0.1-127.0.0.3, 127.0.0.9]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := Load(path); err != nil || f.Validate() != nil || len(f.Survey.Ranges) != 2 {
		t.Errorf("a survey of ranges under sim: %+v, %v", f.Survey, err)
	}
	if err := os.WriteFile(path, []byte("site:\n  adapter: Ethernet 3\nconsumer:\n  adapter: 10.0.0.1\nsurvey:\n  enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := Load(path); err != nil || f.Validate() != nil {
		t.Errorf("a survey of the whole subnet: %v", err)
	}
	for name, text := range map[string]string{
		"bad level":    "sim: default\ncontrol: root\n",
		"bad property": "sim: default\npseudonym:\n  pass_through: [no-such-thing]\n",
		"bad hidden":   "sim: default\npseudonym:\n  hidden_objects: [no-such-type]\n",
		"bad service":  "sim: default\nreserved:\n  services: [who-is]\n",
		"bad sim":      "sim: maybe\n",
		"no adapter":   "site:\n  adapter: x\n",
		"bad bbmd":     "sim: default\nsite:\n  bbmd: nowhere\n",
		"bad clock":    "sim: default\nsurvey:\n  at: noon\n",
		"bad rate":     "sim: default\nsurvey:\n  rate: 0\n",
		"bad range":    "sim: default\nsurvey:\n  ranges: [192.168.1.60-192.168.1.20]\n",
		"sim no range": "sim: default\nsurvey:\n  enabled: true\n",
		"bound off":    "sim: default\nconsumer:\n  max_in_flight: 0\n",
		"bound below":  "sim: default\nsite:\n  max_new_devices_per_minute: -1\n",
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
