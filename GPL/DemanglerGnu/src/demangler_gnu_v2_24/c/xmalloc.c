#include <stdio.h>
#include <stdlib.h>

void *xmalloc (size_t size) {
  void *ptr = malloc (size);
  if (ptr == NULL && size != 0) {
    fprintf (stderr, "xmalloc: out of memory\n");
    exit (1);
  }
  return ptr;
}

void *xrealloc (void *ptr, size_t size) {
  void *new_ptr = realloc (ptr, size);
  if (new_ptr == NULL && size != 0) {
    fprintf (stderr, "xrealloc: out of memory\n");
    exit (1);
  }
  return new_ptr;
}

void *xcalloc (size_t nmemb, size_t size) {
    void *ptr = calloc(nmemb, size);
    if (ptr == NULL && nmemb != 0 && size != 0) {
        fprintf(stderr, "xcalloc: out of memory\n");
        exit(1);
    }
    return ptr;
}
