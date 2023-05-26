#ifndef _SH_UTILS_H_
#define _SH_UTILS_H_
  
char *concat_args(int argc, char **argv);
int tokenize(char *str, char **tokens, size_t tokens_len, char *delim);
int make_args(char *cmd, char **argv, int arg_max);

#endif
