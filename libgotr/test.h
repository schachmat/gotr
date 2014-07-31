#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *m = test(); tests_run++; if (m) return m; } while (0)
extern int tests_run;
