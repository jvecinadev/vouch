<?php // expect: CWE-78
// INTENTIONALLY INSECURE. Benchmark case, never use in production.

function ping($host) {
    return shell_exec("ping -c 1 " . $host);
}
