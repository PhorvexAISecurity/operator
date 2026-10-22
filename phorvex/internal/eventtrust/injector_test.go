package eventtrust

import "testing"

func TestConfigureInjectorInstallsOneServiceAccount(t *testing.T) {
	t.Cleanup(func() { _ = ConfigureInjector("") })
	if Injector() != DefaultInjector {
		t.Fatalf("unconfigured injector = %q", Injector())
	}
	const staging = "system:serviceaccount:phorvex-staging:staging-attacks"
	for _, spelling := range []string{"phorvex-staging/staging-attacks", "phorvex-staging:staging-attacks", staging} {
		if err := ConfigureInjector(spelling); err != nil || Injector() != staging {
			t.Fatalf("ConfigureInjector(%q) = %v, installed %q", spelling, err, Injector())
		}
	}
	for _, bad := range []string{"alice", "Bad_NS/console", "phorvex-staging/", "system:serviceaccount:phorvex-staging"} {
		if err := ConfigureInjector(bad); err == nil {
			t.Fatalf("%q was accepted as an injector", bad)
		}
		if Injector() != staging {
			t.Fatalf("refused %q replaced the injector with %q", bad, Injector())
		}
	}
	if err := ConfigureInjector(""); err != nil || Injector() != DefaultInjector {
		t.Fatalf("empty must restore the default, got %q (%v)", Injector(), err)
	}
}
