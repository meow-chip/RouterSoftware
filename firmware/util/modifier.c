#include <stdio.h>

int main(int argc, char **argv) {
  if(argc != 2) {
    printf("Usage: modifier FILE\n");
    return 1;
  }
  FILE *fp = fopen(argv[1], "r+");
  fseek(fp, 0, SEEK_END);
  size_t len = ftell(fp);

  if(len <= 8) {
    printf("Unexpected file length: %d\n", len);
    return 1;
  }

  printf("file length: %d\n", len);

  fseek(fp, 0, SEEK_SET);

  char buf[8];

  for(int i = 0; i < 8; ++i) {
    buf[i] = len & 0xFF;
    len >>= 8;
  }

  fwrite(buf, 1, 8, fp);
  fclose(fp);
}
