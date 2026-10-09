// expect: CWE-78
// INTENTIONALLY INSECURE. Benchmark case, never use in production.
package main

import "os/exec"

func ping(host string) error {
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}
