// chp_table.h - the per-backend table behind include/chp.h (internal).
#pragma once
typedef struct {
  const char *name;
  int (*fast_parse)(const char *, int, req_t *);
  fp_batch_t (*fast_parse_many)(const char *, int, req_t *, int);
  int (*fast_parse_learn)(const char *, int, req_t *, fp_learn_t *);
  int (*fb_parse_request)(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct fb_header *, size_t *, size_t);
  int (*fb_parse_req)(const char *, int, req_t *);
  int (*fb_parse_req_ex)(const char *, int, req_t *, fb_info_t *);
  void (*bp_parse)(int, const char *const *, const int *, req_t *, int *);
} chp_impl_t;
