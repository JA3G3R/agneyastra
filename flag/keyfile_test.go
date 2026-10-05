package flags

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.txt")
	content := "" +
		"# a comment line\n" +
		"AIzaKEY1,proj-a,proj-b\n" +
		"\n" +
		"   AIzaKEY2   \n" +
		"AIzaKEY1,should-be-ignored-dup\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	keys, err := readKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 unique keys, got %d: %+v", len(keys), keys)
	}
	if keys[0].Key != "AIzaKEY1" || len(keys[0].ProjectIDs) != 2 ||
		keys[0].ProjectIDs[0] != "proj-a" || keys[0].ProjectIDs[1] != "proj-b" {
		t.Fatalf("first key parsed wrong: %+v", keys[0])
	}
	if keys[1].Key != "AIzaKEY2" || len(keys[1].ProjectIDs) != 0 {
		t.Fatalf("second key parsed wrong (whitespace/trim?): %+v", keys[1])
	}
}
