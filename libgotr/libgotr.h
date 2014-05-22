
typedef int (*gotr_cb_send_all)(const char*);
typedef int (*gotr_cb_send_usr)(const char*, const char*);


void gotr_init(gotr_cb_send_all all, gotr_cb_send_usr usr);
/* hi there */
