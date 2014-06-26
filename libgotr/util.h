#define GOTR_STATE_UNKNOWN             ((char)0)
#define GOTR_STATE_CHANNEL_ESTABLISHED ((char)1)
#define GOTR_STATE_FLAKE_GOT_y         ((char)2)
#define GOTR_STATE_FLAKE_GOT_V         ((char)3)
#define GOTR_STATE_FLAKE_VALIDATED     ((char)4)

void gotr_rand_poll();
void gotr_eprintf(const char *format, ...);
